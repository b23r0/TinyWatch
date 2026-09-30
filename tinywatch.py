#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TinyWatch: a dependency-free, cross-platform server monitoring dashboard.

Run with ``python3 tinywatch.py`` and open http://127.0.0.1:8765.
The web UI, HTTP API, collectors, and JSON-backed configuration live in this
single file. Platform-specific collectors use the standard library and native
system interfaces or commands when a portable Python API does not exist.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http.client import HTTPException
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

APP_NAME = "TinyWatch"
APP_VERSION = "1.0.0"
DEFAULT_PORT = 8765
PASSWORD_ITERATIONS = 310_000
MAX_BODY_BYTES = 1_000_000
MAX_ASSETS = 16
MAX_WIDGETS = 32
HISTORY_INTERVAL = 60
HISTORY_RETENTION_DEFAULT_DAYS = 7
HISTORY_RETENTION_OPTIONS = (1, 3, 7, 14, 30)
HISTORY_RETENTION_MAX = 30 * 24 * 60 * 60
HISTORY_RANGES = {"1h": 60 * 60, "6h": 6 * 60 * 60, "24h": 24 * 60 * 60, "3d": 3 * 24 * 60 * 60, "7d": 7 * 24 * 60 * 60, "14d": 14 * 24 * 60 * 60, "30d": 30 * 24 * 60 * 60}
HISTORY_LAST_WRITE = 0.0
SAMPLE_LOCK = threading.RLock()
SNAPSHOT_LOCK = threading.Lock()
SNAPSHOT_CACHE = {"sampled_at": 0.0, "data": None}
STATE_LOCK = threading.RLock()
SESSIONS = {}
LOGIN_FAILURES = {}
PREVIOUS = {"cpu": None, "processes": {}, "network_processes": {}, "interfaces": None, "sampled_at": None}
TICKS_PER_SECOND = None
PAGE_SIZE = 60


def _run(args, timeout=3, input_text=None):
    """Run a native command without a shell; return stdout or an empty string."""
    try:
        result = subprocess.run(
            args, input=input_text, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout, check=False, errors="replace",
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""


def _read_text(path, limit=2_000_000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as stream:
            return stream.read(limit)
    except (OSError, UnicodeError):
        return ""


def _number(value, fallback=0):
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            return fallback


def _human_bytes(value):
    amount = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if amount < 1024 or unit == "PB":
            return ("%.0f %s" if unit == "B" else "%.1f %s") % (amount, unit)
        amount /= 1024
    return "0 B"


def _safe_text(text, limit=240):
    return str(text or "").replace("\x00", "")[:limit]


def _linux_cpu_times():
    values = {}
    for line in _read_text("/proc/stat", 65536).splitlines():
        match = re.match(r"^(cpu(?:\d+)?)\s+([\d ]+)", line)
        if not match:
            continue
        ticks = [int(item) for item in match.group(2).split()]
        if len(ticks) < 4:
            continue
        # Linux reports guest time inside user/nice; subtract it to avoid double counting.
        user = max(0, ticks[0] - (ticks[8] if len(ticks) > 8 else 0))
        nice = max(0, ticks[1] - (ticks[9] if len(ticks) > 9 else 0))
        idle = ticks[3] + (ticks[4] if len(ticks) > 4 else 0)
        total = sum(ticks[:8])
        values[match.group(1)] = (total, idle)
    return values


def _windows_cpu_times():
    """Return aggregate and per-core Windows CPU counters through kernel32."""
    try:
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

            def value(self):
                return (self.high << 32) | self.low

        idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
        if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            return {}
        aggregate = (kernel.value() + user.value(), idle.value())
        return {"cpu": aggregate}
    except (AttributeError, OSError, ImportError):
        return {}


def _bsd_cpu_times():
    system = platform.system().lower()
    if system == "darwin":
        # The Mach host_processor_info API provides cumulative counters per core.
        try:
            import ctypes

            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
            library.mach_host_self.restype = ctypes.c_uint
            host_processor_info = library.host_processor_info
            host_processor_info.argtypes = [ctypes.c_uint, ctypes.c_int,
                                             ctypes.POINTER(ctypes.POINTER(ctypes.c_int)),
                                             ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
            host_processor_info.restype = ctypes.c_int
            data = ctypes.POINTER(ctypes.c_int)()
            data_count = ctypes.c_uint()
            processor_count = ctypes.c_uint()
            status = host_processor_info(library.mach_host_self(), 2, ctypes.byref(data),
                                         ctypes.byref(data_count), ctypes.byref(processor_count))
            if status == 0 and processor_count.value and data_count.value >= processor_count.value * 4:
                raw = ctypes.cast(data, ctypes.POINTER(ctypes.c_int))
                values = {}
                for index in range(processor_count.value):
                    ticks = [raw[index * 4 + offset] & 0xFFFFFFFF for offset in range(4)]
                    values["cpu" + str(index)] = (sum(ticks), ticks[2])
                try:
                    task_port = ctypes.c_uint.in_dll(library, "mach_task_self_").value
                    vm_deallocate = library.vm_deallocate
                    vm_deallocate.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_size_t]
                    vm_deallocate.restype = ctypes.c_int
                    vm_deallocate(task_port, ctypes.cast(data, ctypes.c_void_p),
                                  data_count.value * ctypes.sizeof(ctypes.c_int))
                except (ValueError, AttributeError):
                    pass
                return values
        except (AttributeError, OSError, ImportError, TypeError):
            pass
    if system == "freebsd":
        raw = _run(["sysctl", "-n", "kern.cp_times"])
        numbers = [_number(v) for v in re.findall(r"\d+", raw)]
        if numbers:
            cores = max(1, os.cpu_count() or 1)
            width = max(1, len(numbers) // cores)
            return {"cpu" + str(i): (sum(numbers[i * width:(i + 1) * width]),
                                      sum(numbers[i * width + 4:i * width + width]))
                    for i in range(cores)}
    raw = _run(["sysctl", "-n", "kern.cp_time"])
    numbers = [_number(v) for v in re.findall(r"\d+", raw)]
    if len(numbers) >= 5:
        return {"cpu": (sum(numbers), numbers[4])}
    return {}


def _cpu_snapshot():
    system = platform.system().lower()
    if system == "linux":
        counters = _linux_cpu_times()
    elif system == "windows":
        counters = _windows_cpu_times()
        # PowerShell exposes individual logical processor counters on supported Windows versions.
        if counters:
            raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor | "
                        "Select-Object Name,PercentProcessorTime | ConvertTo-Json -Compress"], timeout=4)
            try:
                rows = json.loads(raw)
                if isinstance(rows, dict):
                    rows = [rows]
                per_core = {"cpu" + str(r.get("Name")): max(0, min(100, float(r.get("PercentProcessorTime", 0))))
                            for r in rows if str(r.get("Name", "_Total")) != "_Total"}
                if per_core:
                    counters["_windows_per_core"] = per_core
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
    else:
        counters = _bsd_cpu_times()

    now = time.monotonic()
    usage = {}
    previous = PREVIOUS.get("cpu")
    if counters:
        for key, values in counters.items():
            if key == "_windows_per_core":
                continue
            if previous and key in previous:
                total_delta = max(0, values[0] - previous[key][0])
                idle_delta = max(0, values[1] - previous[key][1])
                pct = 100.0 * (total_delta - idle_delta) / total_delta if total_delta else 0.0
                usage[key] = max(0.0, min(100.0, pct))
            else:
                usage[key] = 0.0
        if "_windows_per_core" in counters:
            usage.update(counters["_windows_per_core"])
        PREVIOUS["cpu"] = {k: v for k, v in counters.items() if k != "_windows_per_core"}
    else:
        usage["cpu"] = 0.0
    cores = sorted((k, round(v, 1)) for k, v in usage.items() if k != "cpu")
    overall = usage.get("cpu")
    if overall is None:
        overall = sum(v for _, v in cores) / len(cores) if cores else 0.0
    return {"percent": round(max(0.0, min(100.0, overall)), 1), "available": bool(counters),
            "cores": [{"name": name, "percent": percent} for name, percent in cores],
            "logical_cores": os.cpu_count() or 1}


def _memory_snapshot():
    total = available = used = 0
    system = platform.system().lower()
    if system == "linux":
        values = {}
        for line in _read_text("/proc/meminfo", 65536).splitlines():
            match = re.match(r"^(\w+):\s+(\d+)", line)
            if match:
                values[match.group(1)] = int(match.group(2)) * 1024
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", values.get("MemFree", 0) + values.get("Buffers", 0) + values.get("Cached", 0))
        used = max(0, total - available)
    elif system == "windows":
        try:
            import ctypes
            from ctypes import wintypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            info = MEMORYSTATUSEX()
            info.dwLength = ctypes.sizeof(info)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(info)):
                total, available = int(info.ullTotalPhys), int(info.ullAvailPhys)
                used = total - available
        except (AttributeError, OSError, ImportError):
            pass
    elif system == "darwin":
        size = _number(_run(["sysctl", "-n", "hw.memsize"]))
        vm = _run(["vm_stat"])
        page_size_match = re.search(r"page size of (\d+) bytes", vm)
        page_size = _number(page_size_match.group(1), 4096) if page_size_match else 4096
        pages = {}
        for line in vm.splitlines():
            match = re.match(r"([^:]+):\s+(\d+)", line)
            if match:
                pages[match.group(1)] = int(match.group(2))
        total = size
        available = sum(pages.get(label, 0) for label in ("Pages free", "Pages inactive", "Pages speculative", "Pages purgeable")) * page_size
        used = max(0, total - available)
    else:
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            total = os.sysconf("SC_PHYS_PAGES") * page_size
            available = os.sysconf("SC_AVPHYS_PAGES") * page_size
            used = max(0, total - available)
        except (ValueError, OSError, AttributeError):
            pass
    if not total:
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            total = os.sysconf("SC_PHYS_PAGES") * page_size
            available = os.sysconf("SC_AVPHYS_PAGES") * page_size
            used = max(0, total - available)
        except (ValueError, OSError, AttributeError):
            pass
    return {"total": total, "used": used, "available": available,
            "percent": round(100.0 * used / total, 1) if total else 0.0}


def _disk_snapshot():
    mounts = []
    seen = set()
    system = platform.system().lower()
    if system == "linux":
        virtual = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs",
                   "debugfs", "tracefs", "pstore", "efivarfs", "mqueue", "hugetlbfs", "fusectl", "configfs",
                   "overlay", "autofs", "rpc_pipefs", "nsfs", "bpf"}
        for line in _read_text("/proc/self/mounts", 1_000_000).splitlines():
            fields = line.split()
            if len(fields) < 3 or fields[2] in virtual:
                continue
            mount = fields[1].replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
            key = (mount, fields[0])
            if key in seen:
                continue
            seen.add(key)
            mounts.append((mount, fields[0], fields[2]))
    elif system == "windows":
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for index in range(26):
                if mask & (1 << index):
                    mount = chr(65 + index) + ":\\"
                    mounts.append((mount, mount, "drive"))
        except (AttributeError, OSError):
            for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
                mount = letter + ":\\"
                if os.path.exists(mount):
                    mounts.append((mount, mount, "drive"))
    else:
        output = _run(["df", "-P", "-k"], timeout=4)
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                mounts.append((parts[-1], parts[0], "filesystem"))
    result = []
    for mount, device, fs_type in mounts:
        try:
            usage = shutil.disk_usage(mount)
            result.append({"mount": _safe_text(mount, 256), "device": _safe_text(device, 256),
                           "filesystem": _safe_text(fs_type, 80), "total": usage.total,
                           "used": usage.used, "free": usage.free,
                           "percent": round(100.0 * usage.used / usage.total, 1) if usage.total else 0.0})
        except (OSError, ValueError):
            continue
    result.sort(key=lambda item: (item["mount"].count(os.sep), item["mount"]))
    # A partition can be mounted more than once; count its capacity only once.
    unique_spaces = {}
    for item in result:
        unique_spaces.setdefault((item["device"], item["total"]), item)
    total = sum(item["total"] for item in unique_spaces.values())
    used = sum(item["used"] for item in unique_spaces.values())
    return {"partitions": result[:120], "total": total, "used": used,
            "percent": round(100.0 * used / total, 1) if total else 0.0}


def _linux_interfaces():
    result = {}
    for line in _read_text("/proc/net/dev", 65536).splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        values = data.split()
        if len(values) >= 9:
            result[name.strip()] = {"rx": _number(values[0]), "tx": _number(values[8])}
    return result


def _windows_interfaces():
    raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Compress"], timeout=4)
    result = {}
    try:
        rows = json.loads(raw)
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            name = _safe_text(row.get("Name", ""), 100)
            if name:
                result[name] = {"rx": _number(row.get("ReceivedBytes")), "tx": _number(row.get("SentBytes"))}
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return result


def _other_interfaces():
    result = {}
    # netstat -ib exposes byte counters on BSD/macOS; column layouts vary by release.
    output = _run(["netstat", "-ibn"], timeout=4)
    lines = output.splitlines()
    header = None
    for line in lines:
        fields = line.split()
        lowered = [field.lower() for field in fields]
        if "ibytes" in lowered and "obytes" in lowered:
            header = lowered
            continue
        if not header or len(fields) < len(header):
            continue
        try:
            result[fields[0]] = {"rx": _number(fields[header.index("ibytes")]),
                                 "tx": _number(fields[header.index("obytes")])}
        except (ValueError, IndexError):
            continue
    return result


def _network_snapshot():
    system = platform.system().lower()
    current = _linux_interfaces() if system == "linux" else (_windows_interfaces() if system == "windows" else _other_interfaces())
    now = time.monotonic()
    previous = PREVIOUS.get("interfaces")
    interval = max(0.01, now - (PREVIOUS.get("sampled_at") or now))
    interfaces = []
    for name, counters in sorted(current.items()):
        old = previous.get(name) if previous else None
        rx_rate = max(0, counters["rx"] - old["rx"]) / interval if old else 0.0
        tx_rate = max(0, counters["tx"] - old["tx"]) / interval if old else 0.0
        interfaces.append({"name": _safe_text(name, 100), "rx_total": counters["rx"], "tx_total": counters["tx"],
                           "rx_rate": round(rx_rate, 1), "tx_rate": round(tx_rate, 1)})
    PREVIOUS["interfaces"] = current
    PREVIOUS["sampled_at"] = now
    return {"interfaces": interfaces,
            "rx_rate": round(sum(item["rx_rate"] for item in interfaces), 1),
            "tx_rate": round(sum(item["tx_rate"] for item in interfaces), 1)}


def _load_snapshot():
    try:
        parts = [float(value) for value in _read_text("/proc/loadavg", 1024).split()[:3]]
        if len(parts) == 3:
            return parts
    except ValueError:
        pass
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except (AttributeError, OSError):
        pass
    if platform.system().lower() == "windows":
        # Windows has no Unix load average; expose the last-minute CPU utilization as a load proxy.
        return []
    output = _run(["uptime"])
    match = re.search(r"load averages?:\s*([\d.]+)[, ]+([\d.]+)[, ]+([\d.]+)", output)
    return [float(value) for value in match.groups()] if match else []


def _uptime_seconds():
    linux_uptime = _read_text("/proc/uptime", 256).split()
    if linux_uptime:
        try:
            return max(0, int(float(linux_uptime[0])))
        except ValueError:
            pass
    if platform.system().lower() == "windows":
        try:
            import ctypes
            return int(ctypes.windll.kernel32.GetTickCount64() / 1000)
        except (AttributeError, OSError):
            pass
    if platform.system().lower() == "darwin":
        raw = _run(["sysctl", "-n", "kern.boottime"])
        match = re.search(r"sec\s*=\s*(\d+)", raw)
        if match:
            return max(0, int(time.time()) - int(match.group(1)))
    try:
        boot = float(_read_text("/proc/stat", 1_000_000).split("btime ", 1)[1].split()[0])
        return max(0, int(time.time() - boot))
    except (IndexError, ValueError):
        pass
    output = _run(["uptime", "-s"])
    try:
        boot = datetime.strptime(output, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        return max(0, int(time.time() - boot))
    except ValueError:
        return 0


def _format_uptime(seconds):
    days, remainder = divmod(max(0, seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    return (str(days) + "d " if days else "") + "%02dh %02dm" % (hours, minutes)


def _cpu_brand():
    if platform.system().lower() == "linux":
        for line in _read_text("/proc/cpuinfo", 200_000).splitlines():
            if line.lower().startswith(("model name", "hardware", "processor name")) and ":" in line:
                value = line.split(":", 1)[1].strip()
                if value and not value.isdigit():
                    return _safe_text(value, 160)
    if platform.system().lower() == "darwin":
        value = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if value:
            return _safe_text(value, 160)
    value = platform.processor()
    return _safe_text(value or (platform.machine() + " processor"), 160)


def _sessions():
    system = platform.system().lower()
    output = _run(["query", "user"], timeout=3) if system == "windows" else _run(["who"], timeout=3)
    return [_safe_text(line, 240) for line in output.splitlines() if line.strip()][:40]


def _linux_process_network_rates():
    """Estimate per-process TCP rates from Linux ss socket counters when available."""
    if not shutil.which("ss"):
        return None
    output = _run(["ss", "-tinp"], timeout=3)
    if not output:
        return None
    totals = {}
    current_pids = []
    sent = received = 0
    has_counters = False

    def flush():
        if not has_counters:
            return
        for pid in current_pids:
            old = totals.get(pid, (0, 0))
            totals[pid] = (old[0] + sent, old[1] + received)

    for line in output.splitlines():
        if line and not line[0].isspace():
            flush()
            current_pids = [_number(value) for value in re.findall(r"pid=(\d+)", line)]
            sent = received = 0
            has_counters = False
        if not current_pids:
            continue
        sent_match = re.search(r"\bbytes_sent:(\d+)", line)
        if not sent_match:
            sent_match = re.search(r"\bbytes_acked:(\d+)", line)
        recv_match = re.search(r"\bbytes_received:(\d+)", line)
        if sent_match:
            sent = _number(sent_match.group(1))
            has_counters = True
        if recv_match:
            received = _number(recv_match.group(1))
            has_counters = True
    flush()

    now = time.monotonic()
    old_totals = PREVIOUS.get("network_processes", {})
    new_totals = {}
    rates = {}
    for pid, (tx_total, rx_total) in totals.items():
        old = old_totals.get(pid)
        if old:
            elapsed = max(0.01, now - old[2])
            rx_rate = max(0, rx_total - old[1]) / elapsed
            tx_rate = max(0, tx_total - old[0]) / elapsed
        else:
            rx_rate = tx_rate = 0.0
        new_totals[pid] = (tx_total, rx_total, now)
        rates[pid] = {"rx": round(rx_rate, 1), "tx": round(tx_rate, 1)}
    PREVIOUS["network_processes"] = new_totals
    return rates


def _processes_linux():
    global TICKS_PER_SECOND
    if TICKS_PER_SECOND is None:
        try:
            TICKS_PER_SECOND = int(os.sysconf("SC_CLK_TCK"))
        except (ValueError, OSError, AttributeError):
            TICKS_PER_SECOND = 100
    now = time.monotonic()
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError, AttributeError):
        page_size = 4096
    try:
        total_memory = _number(_read_text("/proc/meminfo", 65536).split("MemTotal:", 1)[1].split()[0]) * 1024
    except (IndexError, ValueError):
        total_memory = 0
    rows = []
    network_rates = _linux_process_network_rates()
    new_previous = {}
    try:
        entries = os.scandir("/proc")
    except OSError:
        return []
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            stat = _read_text("/proc/" + entry.name + "/stat", 8192)
            if not stat:
                continue
            close = stat.rfind(")")
            if close < 0:
                continue
            command = stat[stat.find("(") + 1:close]
            fields = stat[close + 2:].split()
            try:
                state = fields[0]
                cpu_seconds = (_number(fields[11]) + _number(fields[12])) / TICKS_PER_SECOND
                rss = max(0, _number(fields[21])) * page_size
                uid = None
                for line in _read_text("/proc/" + entry.name + "/status", 32768).splitlines():
                    if line.startswith("Uid:"):
                        uid = _number(line.split()[1])
                        break
                old = PREVIOUS["processes"].get(pid)
                elapsed = max(0.01, now - old[1]) if old else 0
                cpu_pct = max(0.0, min(100.0 * (os.cpu_count() or 1),
                                       100.0 * (cpu_seconds - old[0]) / elapsed)) if old and elapsed else 0.0
                new_previous[pid] = (cpu_seconds, now)
                process_network = network_rates.get(pid) if network_rates is not None else None
                rows.append({"pid": pid, "name": _safe_text(command, 100), "user": str(uid) if uid is not None else "—",
                             "state": state, "cpu": round(cpu_pct, 1), "memory": rss,
                             "memory_percent": round(100.0 * rss / total_memory, 2) if total_memory else 0.0,
                             "network_connections": _process_connection_count(pid),
                             "network_rx_rate": process_network["rx"] if process_network else None,
                             "network_tx_rate": process_network["tx"] if process_network else None,
                             "network_supported": network_rates is not None})
            except (IndexError, ValueError, OSError):
                continue
    PREVIOUS["processes"] = new_previous
    rows.sort(key=lambda row: (row["cpu"], row["memory"]), reverse=True)
    return rows[:PAGE_SIZE]


def _process_connection_count(pid):
    try:
        count = 0
        with os.scandir("/proc/" + str(pid) + "/fd") as fds:
            for fd in fds:
                try:
                    target = os.readlink(fd.path)
                    if target.startswith("socket:["):
                        count += 1
                except OSError:
                    continue
        return count
    except OSError:
        return 0


def _processes_windows():
    command = ("Get-CimInstance Win32_Process | Select-Object ProcessId,Name,WorkingSetSize,KernelModeTime,UserModeTime "
               "| ConvertTo-Json -Compress")
    raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], timeout=6)
    try:
        items = json.loads(raw)
        if isinstance(items, dict):
            items = [items]
    except (TypeError, ValueError, json.JSONDecodeError):
        items = []
    now = time.monotonic()
    previous = PREVIOUS["processes"]
    current = {}
    rows = []
    for item in items:
        pid = _number(item.get("ProcessId"))
        if not pid:
            continue
        cpu_seconds = (_number(item.get("KernelModeTime")) + _number(item.get("UserModeTime"))) / 10_000_000
        old = previous.get(pid)
        elapsed = max(0.01, now - old[1]) if old else 0
        cpu_pct = max(0.0, min(100.0 * (os.cpu_count() or 1),
                               100.0 * (cpu_seconds - old[0]) / elapsed)) if old and elapsed else 0.0
        memory = _number(item.get("WorkingSetSize"))
        current[pid] = (cpu_seconds, now)
        rows.append({"pid": pid, "name": _safe_text(item.get("Name", ""), 100), "user": "—", "state": "—",
                     "cpu": round(cpu_pct, 1), "memory": memory, "memory_percent": 0.0,
                     "network_connections": None})
    PREVIOUS["processes"] = current
    total = _memory_snapshot()["total"]
    for row in rows:
        row["memory_percent"] = round(100.0 * row["memory"] / total, 2) if total else 0.0
    rows.sort(key=lambda row: (row["cpu"], row["memory"]), reverse=True)
    return rows[:PAGE_SIZE]


def _processes_other():
    output = _run(["ps", "-axo", "pid=,pcpu=,pmem=,rss=,state=,comm="], timeout=4)
    rows = []
    for line in output.splitlines():
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        pid, cpu, mem, rss, state, name = parts
        rows.append({"pid": _number(pid), "name": _safe_text(name, 100), "user": "—", "state": state,
                     "cpu": round(float(cpu), 1) if cpu.replace(".", "", 1).isdigit() else 0.0,
                     "memory": _number(rss) * 1024,
                     "memory_percent": round(float(mem), 2) if mem.replace(".", "", 1).isdigit() else 0.0,
                     "network_connections": None})
    rows.sort(key=lambda row: (row["cpu"], row["memory"]), reverse=True)
    return rows[:PAGE_SIZE]


def _login_events():
    system = platform.system().lower()
    events = []
    if system == "linux":
        for path in ("/var/log/auth.log", "/var/log/secure"):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as stream:
                    lines = stream.readlines()[-2000:]
            except OSError:
                continue
            for line in lines:
                lowered = line.lower()
                if not any(token in lowered for token in ("sshd", "xrdp", "3389", "remote desktop")):
                    continue
                if not re.search(r"(accepted|failed|invalid user|session opened|session closed|login|disconnect)", lowered):
                    continue
                kind = "RDP" if ("xrdp" in lowered or "3389" in lowered or "remote desktop" in lowered) else "SSH"
                events.append({"kind": kind, "message": _safe_text(line.strip(), 320)})
            if events:
                break
        if not events and shutil.which("journalctl"):
            output = _run(["journalctl", "-n", "200", "--no-pager", "-o", "short-iso"], timeout=5)
            for line in output.splitlines():
                lowered = line.lower()
                if any(token in lowered for token in ("sshd", "xrdp")) and re.search(r"(accepted|failed|session|login)", lowered):
                    events.append({"kind": "RDP" if "xrdp" in lowered else "SSH", "message": _safe_text(line, 320)})
    elif system == "windows":
        powershell = ("Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} -MaxEvents 80 -ErrorAction SilentlyContinue "
                      "| ForEach-Object { [PSCustomObject]@{Time=$_.TimeCreated.ToString('s');Id=$_.Id;Message=$_.Message} } "
                      "| ConvertTo-Json -Compress")
        raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", powershell], timeout=7)
        try:
            items = json.loads(raw)
            if isinstance(items, dict):
                items = [items]
            for item in items:
                msg = _safe_text(item.get("Message", ""), 280)
                # Logon type 10 is RemoteInteractive (RDP); type 3 is commonly network access.
                kind = "RDP" if "Logon Type:\t\t10" in msg or "Logon Type: 10" in msg else "Windows"
                events.append({"kind": kind, "message": _safe_text(str(item.get("Time", "")) + " " + msg, 320)})
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    else:
        output = _run(["last", "-n", "40"], timeout=4)
        for line in output.splitlines():
            if re.search(r"ssh|xrdp|tty|pts", line, re.I):
                events.append({"kind": "SSH", "message": _safe_text(line, 320)})
    events.reverse()
    return events[:80]


def _dns_cache():
    system = platform.system().lower()
    entries = []
    source = ""
    if system == "windows":
        source = "Windows DNS Client cache"
        command = "Get-DnsClientCache | Select-Object Entry,Type,Data | ConvertTo-Json -Compress"
        raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], timeout=5)
        try:
            rows = json.loads(raw)
            if isinstance(rows, dict):
                rows = [rows]
            for row in rows:
                entries.append({"name": _safe_text(row.get("Entry", ""), 180),
                                "type": _safe_text(row.get("Type", ""), 40),
                                "value": _safe_text(row.get("Data", ""), 180)})
        except (TypeError, ValueError, json.JSONDecodeError):
            entries = []
        output = _run(["ipconfig", "/displaydns"], timeout=5) if not entries else ""
        current = {}
        for line in output.splitlines():
            if "Record Name" in line:
                if current:
                    entries.append(current)
                current = {"name": _safe_text(line.split(":", 1)[-1].strip(), 180)}
            elif "Record Type" in line and current:
                current["type"] = _safe_text(line.split(":", 1)[-1].strip(), 40)
            elif ("A (Host) Record" in line or "AAAA AAAA Record" in line) and current:
                current["value"] = _safe_text(line.split(":", 1)[-1].strip(), 180)
        if current:
            entries.append(current)
    elif system == "darwin":
        output = _run(["dscacheutil", "-cachedump", "-entries", "Host"], timeout=5)
        source = "Directory Service host cache"
        for line in output.splitlines():
            match = re.search(r"name:\s*(\S+).*?(?:ipv4_address|ipv6_address):\s*(\S+)", line)
            if match:
                entries.append({"name": _safe_text(match.group(1), 180), "type": "Host", "value": _safe_text(match.group(2), 180)})
    else:
        output = _run(["resolvectl", "show-cache"], timeout=4) or _run(["systemd-resolve", "--statistics"], timeout=4)
        source = "systemd-resolved cache"
        for line in output.splitlines():
            match = re.search(r"(?:IN\s+)?(A|AAAA|CNAME|PTR)\s+([^\s]+)\s+(.+)$", line.strip(), re.I)
            if match:
                entries.append({"name": _safe_text(match.group(2), 180), "type": _safe_text(match.group(1).upper(), 16),
                                "value": _safe_text(match.group(3), 180)})
    if not entries and system != "windows":
        # A visible fallback is preferable to claiming the resolver cache is empty.
        for line in _read_text("/etc/hosts", 128_000).splitlines():
            line = line.split("#", 1)[0].strip()
            fields = line.split()
            if len(fields) >= 2:
                for name in fields[1:]:
                    entries.append({"name": _safe_text(name, 180), "type": "hosts", "value": _safe_text(fields[0], 180)})
        source = "hosts file (resolver cache not exposed)"
    unique = []
    seen = set()
    for item in entries:
        key = (item.get("name"), item.get("type"), item.get("value"))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return {"source": source, "count": len(unique), "entries": unique[:100]}


def collect_snapshot():
    """Return a shared recent sample so concurrent dashboard requests do not rescan the host."""
    with SNAPSHOT_LOCK:
        now = time.monotonic()
        cached = SNAPSHOT_CACHE["data"]
        if cached is not None and now - SNAPSHOT_CACHE["sampled_at"] < 2.0:
            return cached
        data = _collect_snapshot_now()
        SNAPSHOT_CACHE["sampled_at"] = time.monotonic()
        SNAPSHOT_CACHE["data"] = data
        return data


def _collect_snapshot_now():
    """Collect current host metrics and return JSON-safe, bounded data."""
    with SAMPLE_LOCK:
        cpu = _cpu_snapshot()
        memory = _memory_snapshot()
        disks = _disk_snapshot()
        network = _network_snapshot()
        load = _load_snapshot()
        if platform.system().lower() == "windows" and not load:
            load = [round(cpu["percent"] / 100.0, 2)]
        if platform.system().lower() == "linux":
            processes = _processes_linux()
        elif platform.system().lower() == "windows":
            processes = _processes_windows()
        else:
            processes = _processes_other()
        uname = platform.uname()
        info = {"hostname": _safe_text(socket.gethostname(), 160), "cpu": _cpu_brand(),
                "logical_cores": os.cpu_count() or 1, "memory_total": memory["total"],
                "system": _safe_text(platform.platform(), 240), "os": _safe_text(uname.system, 80),
                "release": _safe_text(uname.release, 120), "version": _safe_text(uname.version, 220),
                "architecture": _safe_text(uname.machine, 80), "uptime_seconds": _uptime_seconds(),
                "uptime": _format_uptime(_uptime_seconds()), "sessions": _sessions(),
                "python": platform.python_version()}
        return {"sampled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "cpu": cpu, "memory": memory, "disk": disks, "network": network, "load": load,
                "processes": processes, "logins": _login_events(), "dns": _dns_cache(), "info": info}


def default_store_path():
    override = os.environ.get("TINYWATCH_DATA")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".tinywatch" / "data.json"


def empty_database():
    return {"schema": 1, "password": None, "agent_token": secrets.token_urlsafe(32),
            "assets": [], "history": {}, "history_retention_days": HISTORY_RETENTION_DEFAULT_DAYS, "widgets": [{"id": "local-cpu", "node": "local", "metric": "cpu"},
                                       {"id": "local-memory", "node": "local", "metric": "memory"},
                                       {"id": "local-network", "node": "local", "metric": "network"},
                                       {"id": "local-disk", "node": "local", "metric": "disk"},
                                       {"id": "local-load", "node": "local", "metric": "load"},
                                       {"id": "local-processes", "node": "local", "metric": "processes"},
                                       {"id": "local-logins", "node": "local", "metric": "logins"},
                                       {"id": "local-dns", "node": "local", "metric": "dns"},
                                       {"id": "local-info", "node": "local", "metric": "info"}],
            "theme": "dark"}


def _prune_history_database(database, cutoff):
    history = database.get("history")
    if not isinstance(history, dict):
        return False
    changed = False
    for node_series in history.values():
        if not isinstance(node_series, dict):
            continue
        for metric, points in list(node_series.items()):
            if isinstance(points, list):
                filtered = [point for point in points
                            if isinstance(point, list) and point and _number(point[0]) >= cutoff]
                if len(filtered) != len(points):
                    changed = True
                node_series[metric] = filtered
    return changed


class JsonStore:
    """Atomic JSON store with one known-good backup and startup recovery."""

    def __init__(self, path):
        self.path = Path(path)
        self.backup_path = self.path.with_name(self.path.name + ".bak")
        self.lock = threading.RLock()
        self.recovered_from_backup = False
        self.persisted_retention_days = None
        self._known_main_signature = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()
        self.persisted_retention_days = self._retention_days(self.data)
        cutoff = time.time() - self.persisted_retention_days * 24 * 60 * 60
        pruned = _prune_history_database(self.data, cutoff)
        if not self.recovered_from_backup and self._valid_database_file(self.path):
            self._known_main_signature = self._file_signature(self.path)
        if self.recovered_from_backup or pruned:
            self.save(backup_retention_days=self.persisted_retention_days)

    @staticmethod
    def _retention_days(database):
        days = database.get("history_retention_days", HISTORY_RETENTION_DEFAULT_DAYS)
        if isinstance(days, bool) or days not in HISTORY_RETENTION_OPTIONS:
            return HISTORY_RETENTION_DEFAULT_DAYS
        return days

    @staticmethod
    def _file_signature(path):
        stat = path.stat()
        return stat.st_size, getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1_000_000_000))

    @staticmethod
    def _read_database(path):
        try:
            with path.open("r", encoding="utf-8") as stream:
                value = json.load(stream)
        except FileNotFoundError:
            return None, None
        except (OSError, UnicodeError, ValueError) as exc:
            return None, exc
        if not isinstance(value, dict) or value.get("schema") != 1:
            return None, ValueError("unsupported or invalid database schema")
        default = empty_database()
        default.update(value)
        return default, None

    def _preserve_corrupt_file(self):
        if not self.path.exists():
            return
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        damaged = self.path.with_name(self.path.name + ".corrupt-" + stamp)
        suffix = 1
        while damaged.exists():
            damaged = self.path.with_name(self.path.name + ".corrupt-" + stamp + "-" + str(suffix))
            suffix += 1
        try:
            shutil.copy2(self.path, damaged)
            try:
                os.chmod(damaged, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise ValueError("database backup recovery failed; original file was left untouched: " + str(exc))

    def _load(self):
        primary, primary_error = self._read_database(self.path)
        if primary is not None:
            return primary
        backup, backup_error = self._read_database(self.backup_path)
        if backup is not None:
            if primary_error is not None:
                self._preserve_corrupt_file()
            self.recovered_from_backup = True
            return backup
        if primary_error is None and backup_error is None:
            return empty_database()
        damaged_path = self.path if primary_error is not None else self.backup_path
        raise ValueError("database is unreadable and no valid backup is available: " + str(damaged_path))

    @staticmethod
    def _write_synced(path, content):
        with path.open("wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    @staticmethod
    def _valid_database_file(path):
        try:
            with path.open("r", encoding="utf-8") as stream:
                value = json.load(stream)
            return isinstance(value, dict) and value.get("schema") == 1
        except (OSError, UnicodeError, ValueError):
            return False

    def _main_is_known_good(self):
        try:
            signature = self._file_signature(self.path)
        except OSError:
            return False
        if signature == self._known_main_signature:
            return True
        if self._valid_database_file(self.path):
            self._known_main_signature = signature
            return True
        return False

    def _sync_parent_directory(self):
        if os.name == "nt":
            return
        try:
            descriptor = os.open(str(self.path.parent), os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            pass

    def save(self, backup_retention_days=None):
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + ".tmp")
            backup_temporary = self.backup_path.with_name(self.backup_path.name + ".tmp")
            encoded = json.dumps(self.data, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
            self._write_synced(temporary, encoded)
            if self._main_is_known_good():
                if backup_retention_days is not None:
                    with self.path.open("r", encoding="utf-8") as current:
                        previous = json.load(current)
                    previous["history_retention_days"] = backup_retention_days
                    _prune_history_database(previous, time.time() - backup_retention_days * 24 * 60 * 60)
                    backup_content = json.dumps(previous, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
                    self._write_synced(backup_temporary, backup_content)
                else:
                    with self.path.open("rb") as current, backup_temporary.open("wb") as backup:
                        shutil.copyfileobj(current, backup)
                        backup.flush()
                        os.fsync(backup.fileno())
                    try:
                        os.chmod(backup_temporary, 0o600)
                    except OSError:
                        pass
                os.replace(backup_temporary, self.backup_path)
            elif self.recovered_from_backup and backup_retention_days is not None:
                self._write_synced(backup_temporary, encoded)
                os.replace(backup_temporary, self.backup_path)
            os.replace(temporary, self.path)
            self._known_main_signature = self._file_signature(self.path)
            self.persisted_retention_days = self._retention_days(self.data)
            self._sync_parent_directory()


STORE = None


def _password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return {"salt": base64.b64encode(salt).decode("ascii"), "hash": base64.b64encode(digest).decode("ascii"),
            "iterations": PASSWORD_ITERATIONS}


def _password_matches(password, record):
    try:
        salt = base64.b64decode(record["salt"], validate=True)
        expected = base64.b64decode(record["hash"], validate=True)
        iterations = max(100_000, min(1_000_000, _number(record.get("iterations"), PASSWORD_ITERATIONS)))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(actual, expected)
    except (KeyError, TypeError, ValueError):
        return False


def _validate_asset_url(value):
    value = str(value or "").strip()
    if len(value) > 300:
        raise ValueError("资产地址过长")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("资产地址必须是完整的 http:// 或 https:// 地址")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("资产端口无效")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("资产端口范围应为 1–65535")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _config_for_browser():
    with STORE.lock:
        return {"assets": [_public_asset(item) for item in STORE.data.get("assets", [])],
                "widgets": STORE.data.get("widgets", []), "theme": STORE.data.get("theme", "dark"),
                "history_retention_days": _history_retention_days(),
                "agent_token": STORE.data.get("agent_token", ""),
                "storage_recovered": STORE.recovered_from_backup}


def _history_retention_days():
    if STORE is None:
        return HISTORY_RETENTION_DEFAULT_DAYS
    with STORE.lock:
        days = STORE.data.get("history_retention_days", HISTORY_RETENTION_DEFAULT_DAYS)
    if isinstance(days, bool) or days not in HISTORY_RETENTION_OPTIONS:
        return HISTORY_RETENTION_DEFAULT_DAYS
    return days


def _history_retention_seconds():
    return _history_retention_days() * 24 * 60 * 60


def _public_asset(asset):
    parsed = urllib.parse.urlsplit(asset["url"])
    return {"id": asset["id"], "name": asset["name"], "url": asset["url"],
            "secure_transport": parsed.scheme == "https" or _is_loopback_host(parsed.hostname)}


def _is_loopback_host(hostname):
    normalized = str(hostname or "").strip("[]").lower().rstrip(".")
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward the agent token to a redirect target."""

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _remote_snapshot(asset):
    parsed = urllib.parse.urlsplit(asset["url"])
    if parsed.scheme != "https" and not _is_loopback_host(parsed.hostname):
        return {"id": asset["id"], "name": asset["name"], "online": False,
                "error": "远程资产必须使用 HTTPS；HTTP 仅限 localhost / 回环地址", "metrics": None}
    endpoint = asset["url"].rstrip("/") + "/api/agent/metrics"
    request = urllib.request.Request(endpoint, headers={"X-TinyWatch-Token": asset["password"],
                                                        "Accept": "application/json", "User-Agent": "TinyWatch/" + APP_VERSION})
    try:
        opener = urllib.request.build_opener(_RejectRedirectHandler())
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise OSError("HTTP " + str(response.status))
            payload = response.read(2_000_000)
            data = json.loads(payload.decode("utf-8"))
            if not isinstance(data, dict) or "info" not in data or "cpu" not in data:
                raise ValueError("invalid metric response")
            return {"id": asset["id"], "name": asset["name"], "online": True, "metrics": data}
    except (OSError, urllib.error.URLError, HTTPException, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        return {"id": asset["id"], "name": asset["name"], "online": False,
                "error": _safe_text(reason, 140), "metrics": None}


def _record_history(nodes, now=None):
    """Persist a compact cluster sample at most once per minute."""
    global HISTORY_LAST_WRITE
    if STORE is None:
        return
    now = time.time() if now is None else now
    with STORE.lock:
        if now - HISTORY_LAST_WRITE < HISTORY_INTERVAL:
            return
        history = STORE.data.setdefault("history", {})
        if not isinstance(history, dict):
            history = STORE.data["history"] = {}
        cutoff = now - _history_retention_seconds()
        for node_id, node in nodes.items():
            metrics = node.get("metrics") if node.get("online") else None
            if not isinstance(metrics, dict):
                continue
            series = history.setdefault(str(node_id), {})
            if not isinstance(series, dict):
                series = history[str(node_id)] = {}
            cpu = metrics.get("cpu") or {}
            memory = metrics.get("memory") or {}
            disk = metrics.get("disk") or {}
            network = metrics.get("network") or {}
            load = metrics.get("load") or []
            interfaces = {}
            for item in network.get("interfaces", []):
                if isinstance(item, dict) and item.get("name"):
                    interfaces[str(item["name"])[:120]] = [
                        max(0, _number(item.get("rx_rate"))), max(0, _number(item.get("tx_rate")))
                    ]
            if not interfaces:
                interfaces["total"] = [max(0, _number(network.get("rx_rate"))),
                                       max(0, _number(network.get("tx_rate")))]
            samples = {
                "cpu": [round(_number(cpu.get("percent")), 2)],
                "memory": [round(_number(memory.get("used"))), round(_number(memory.get("total"))),
                           round(_number(memory.get("percent")), 2)],
                "disk": [round(_number(disk.get("used"))), round(_number(disk.get("total"))),
                         round(_number(disk.get("percent")), 2)],
                "network": [interfaces],
                "load": [round(_number(value), 3) for value in load[:3]],
            }
            for metric, values in samples.items():
                points = series.setdefault(metric, [])
                if not isinstance(points, list):
                    points = series[metric] = []
                points.append([int(now)] + values)
        _prune_history_database(STORE.data, cutoff)
        STORE.save()
        HISTORY_LAST_WRITE = now


def _history_response(node_id, metric, range_name, interface="", start=None, end=None):
    now = time.time()
    if range_name == "custom":
        if start is None or end is None or not math.isfinite(start) or not math.isfinite(end):
            raise ValueError("自定义历史查询需要有效的起止时间")
        if start >= end or end > now + 60:
            raise ValueError("起始时间必须早于结束时间，且结束时间不能在未来")
        retention_seconds = _history_retention_seconds()
        if end - start > retention_seconds or start < now - retention_seconds:
            raise ValueError("所选时间超出当前数据保留期限")
        lower_bound, upper_bound = start, min(end, now)
    else:
        lower_bound = now - HISTORY_RANGES[range_name]
        upper_bound = now
    with STORE.lock:
        all_history = STORE.data.get("history", {})
        if not isinstance(all_history, dict):
            all_history = {}
        node_history = all_history.get(node_id, {})
        points = node_history.get(metric, []) if isinstance(node_history, dict) else []
        result = []
        for point in points:
            if not isinstance(point, list) or not point:
                continue
            timestamp = _number(point[0])
            if timestamp < lower_bound or timestamp > upper_bound:
                continue
            if metric == "network":
                interfaces = point[1] if len(point) > 1 and isinstance(point[1], dict) else {}
                if interface:
                    rates = interfaces.get(interface, [0, 0])
                else:
                    rates = [sum(_number(rate[i]) for rate in interfaces.values()
                                 if isinstance(rate, list) and len(rate) > i) for i in range(2)]
                result.append([point[0], round(_number(rates[0]), 2), round(_number(rates[1]), 2)])
            elif metric in ("cpu", "load"):
                if len(point) > 1:
                    result.append([point[0], point[1]])
            elif metric in ("memory", "disk") and len(point) > 3:
                result.append([point[0], point[1], point[2], point[3]])
    return {"node": node_id, "metric": metric, "range": range_name, "interface": interface,
            "start": start, "end": end, "points": result}


def collect_cluster_snapshot():
    nodes = {"local": {"id": "local", "name": socket.gethostname(), "online": True, "metrics": collect_snapshot()}}
    with STORE.lock:
        assets = list(STORE.data.get("assets", []))[:MAX_ASSETS]
    if assets:
        with ThreadPoolExecutor(max_workers=min(8, len(assets))) as pool:
            futures = [pool.submit(_remote_snapshot, item) for item in assets]
            for future in as_completed(futures):
                result = future.result()
                nodes[result["id"]] = result
    _record_history(nodes)
    return {"nodes": nodes, "sampled_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


def _history_sampler(stop_event):
    """Collect cluster metrics in the background while the service is running."""
    while not stop_event.is_set():
        try:
            collect_cluster_snapshot()
        except Exception as exc:
            sys.stderr.write("TinyWatch history sampler: %s\n" % _safe_text(exc, 180))
        if stop_event.wait(HISTORY_INTERVAL):
            break


HTML_PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light"><title>TinyWatch · Infrastructure</title>
<style>
:root{color-scheme:dark;--bg:#080d18;--surface:#111a2a;--surface2:#172338;--surface3:#1c2a42;--text:#e8f0ff;--muted:#8fa2bf;--line:rgba(149,177,220,.13);--accent:#64e2c3;--accent2:#72a7ff;--warn:#ffca6a;--bad:#ff6b82;--shadow:0 22px 65px rgba(0,0,0,.3);--grid:rgba(148,174,213,.11)}
[data-theme=light]{color-scheme:light;--bg:#eff4fb;--surface:#fff;--surface2:#f4f7fc;--surface3:#e8eef8;--text:#18253b;--muted:#71809a;--line:rgba(45,68,105,.12);--accent:#087f70;--accent2:#326dd7;--warn:#a56400;--bad:#c53b53;--shadow:0 18px 45px rgba(41,63,101,.12);--grid:rgba(45,68,105,.1)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 52% -18%,rgba(72,117,193,.16),transparent 45%),var(--bg);color:var(--text);font:14px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}button,input,select{font:inherit}button{cursor:pointer}a{color:inherit;text-decoration:none}.shell{min-height:100vh;display:grid;grid-template-columns:238px 1fr;align-items:start}.sidebar{padding:25px 16px 20px;border-right:1px solid var(--line);background:rgba(7,12,22,.26);display:flex;flex-direction:column;gap:28px}.brand{display:flex;align-items:center;gap:12px;padding:3px 12px}.brand-mark{width:37px;height:37px;display:grid;place-items:center;border-radius:13px;color:#071a1a;background:linear-gradient(145deg,#74f0ca,#5da7fd);font-size:20px;box-shadow:0 8px 24px rgba(94,221,193,.23)}.brand strong{font-size:17px;letter-spacing:.02em}.brand small{display:block;color:var(--muted);font-size:10px;letter-spacing:.15em;margin-top:2px}.nav-title{color:#70829f;font-size:10px;letter-spacing:.17em;padding:0 12px;margin-bottom:8px}.nav{display:grid;gap:5px}.nav button{border:0;color:var(--muted);background:transparent;text-align:left;padding:11px 13px;border-radius:11px;display:flex;align-items:center;gap:12px}.nav button:hover,.nav button.active{background:var(--surface2);color:var(--text)}.nav button.active{box-shadow:inset 2px 0 var(--accent)}.nav-icon{width:18px;text-align:center;font-size:16px;color:var(--accent)}.sidebar-foot{margin-top:auto;padding:13px;background:var(--surface);border:1px solid var(--line);border-radius:14px;color:var(--muted);font-size:11px}.host-chip{display:flex;align-items:center;gap:8px;color:var(--text);font-size:12px;margin-bottom:8px}.dot{width:8px;height:8px;background:var(--accent);border-radius:50%;box-shadow:0 0 13px var(--accent)}
.main{min-width:0;padding:25px 34px 40px;max-width:1800px;width:100%;margin:0 auto;align-self:start}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:29px}.eyebrow{font-size:10px;color:var(--accent);letter-spacing:.18em;text-transform:uppercase}.page-title{font-size:26px;letter-spacing:-.04em;margin:4px 0 0}.top-actions{display:flex;align-items:center;gap:9px}.status-pill,.chip{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--surface);border-radius:99px;padding:7px 11px;color:var(--muted);font-size:11px}.status-pill .dot{width:6px;height:6px}.icon-button,.button{border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--text);padding:9px 12px}.icon-button{width:39px;height:39px;display:grid;place-items:center;font-size:16px}.button.primary{border-color:transparent;background:linear-gradient(130deg,#64e2c3,#58a5ec);color:#07151b;font-weight:700}.button.subtle{background:var(--surface2);color:var(--muted)}.button.danger{color:var(--bad)}.button:hover,.icon-button:hover{filter:brightness(1.12)}.overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin-bottom:20px}.stat{position:relative;overflow:hidden;background:linear-gradient(145deg,var(--surface),var(--surface2));border:1px solid var(--line);border-radius:16px;padding:16px 17px;min-height:113px}.stat:after{content:"";position:absolute;width:100px;height:100px;right:-40px;top:-53px;border-radius:50%;background:radial-gradient(circle,rgba(100,226,195,.13),transparent 70%)}.stat-label{font-size:11px;color:var(--muted);display:flex;justify-content:space-between;align-items:center}.stat-value{font-size:26px;letter-spacing:-.04em;font-weight:650;margin:11px 0 4px}.stat-foot{font-size:10px;color:var(--muted)}.stat-accent{color:var(--accent)}.section-head{display:flex;align-items:end;justify-content:space-between;margin:25px 0 12px;gap:12px}.section-head h2{font-size:14px;margin:0;letter-spacing:.01em}.section-head p{font-size:11px;color:var(--muted);margin:3px 0 0}.dashboard{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:13px}.widget{position:relative;grid-column:span 4;min-width:0;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:15px 16px;box-shadow:0 8px 26px rgba(0,0,0,.05);transition:border-color .16s,transform .16s}.widget.wide{grid-column:span 8}.widget.full{grid-column:1/-1}.widget.dragging{opacity:.5;border-color:var(--accent);transform:scale(.99)}.widget.drag-over{border-color:var(--accent);box-shadow:0 0 0 2px rgba(100,226,195,.1)}.widget-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:14px}.widget-title{display:flex;align-items:center;gap:9px;font-size:12px;font-weight:650}.widget-title i{font-style:normal;width:26px;height:26px;display:grid;place-items:center;border-radius:8px;background:var(--surface3);color:var(--accent);font-size:13px}.widget-node{font-size:9px;color:var(--muted);font-weight:500}.widget-tools{display:flex;align-items:center;gap:6px}.select-mini{max-width:130px;background:var(--surface2);border:1px solid var(--line);color:var(--muted);font-size:10px;border-radius:7px;padding:5px}.remove-widget{border:0;background:transparent;color:var(--muted);font-size:16px;padding:0 4px}.remove-widget:hover{color:var(--bad)}.big-value{font-size:29px;font-weight:650;letter-spacing:-.05em}.big-value small{font-size:12px;letter-spacing:0;color:var(--muted);font-weight:500}.metric-sub{font-size:10px;color:var(--muted);margin-top:3px}.mini-chart{height:52px;width:100%;margin-top:8px;overflow:visible}.mini-chart .area{fill:rgba(100,226,195,.1)}.mini-chart .line{fill:none;stroke:var(--accent);stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}.history-point{fill:var(--accent);stroke:var(--surface);stroke-width:2}.chart-empty{height:52px;margin-top:8px;display:grid;place-items:center;color:var(--muted);font-size:10px;border-top:1px solid var(--line)}.bar-row{display:grid;grid-template-columns:56px 1fr 42px;align-items:center;gap:8px;margin:8px 0;font-size:10px;color:var(--muted)}.track{height:6px;border-radius:10px;background:var(--surface3);overflow:hidden}.track span{display:block;height:100%;border-radius:10px;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width .35s}.core-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-top:12px}.core{background:var(--surface2);border-radius:7px;padding:6px}.core label{font-size:8px;color:var(--muted);display:flex;justify-content:space-between}.core .track{height:3px;margin-top:5px}.duo{display:grid;grid-template-columns:1fr 1fr;gap:12px}.duo-box{background:var(--surface2);border-radius:10px;padding:10px}.duo-box label{font-size:9px;color:var(--muted);display:block;margin-bottom:4px}.duo-box strong{font-size:14px}.disk-line{display:flex;justify-content:space-between;color:var(--muted);font-size:10px;padding:7px 0;border-bottom:1px solid var(--line)}.disk-line:last-child{border:0}.data-table{width:100%;border-collapse:collapse;font-size:10px}.data-table th{text-align:left;color:var(--muted);font-weight:500;padding:8px 7px;border-bottom:1px solid var(--line)}.data-table td{padding:8px 7px;border-bottom:1px solid var(--line);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.data-table tr:last-child td{border-bottom:0}.tag{font-size:9px;padding:3px 6px;background:var(--surface3);border-radius:5px;color:var(--muted)}.tag.good{color:var(--accent)}.tag.bad{color:var(--bad)}.empty{color:var(--muted);font-size:11px;padding:16px 0}.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.info-item label{color:var(--muted);font-size:9px;display:block}.info-item strong{display:block;font-size:11px;font-weight:550;margin-top:3px;overflow-wrap:anywhere}.notice{color:var(--muted);font-size:10px;margin-top:10px;line-height:1.55}.asset-error{border:1px solid rgba(255,107,130,.2);background:rgba(255,107,130,.05);border-radius:10px;padding:12px;color:var(--bad);font-size:11px}.asset-chip{display:inline-flex;align-items:center;gap:7px;background:var(--surface2);border:1px solid var(--line);border-radius:8px;padding:6px 9px;font-size:10px;margin:3px;color:var(--muted)}.modal-backdrop{position:fixed;inset:0;background:rgba(3,7,14,.66);backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:22px;z-index:20}.modal-backdrop.open{display:flex}.modal{width:min(600px,100%);max-height:85vh;overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:22px}.modal.wide-modal{width:min(900px,100%)}.modal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}.modal-head h3{font-size:16px;margin:0}.close{border:0;background:var(--surface2);border-radius:8px;color:var(--muted);width:30px;height:30px}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{display:grid;gap:6px}.field.full{grid-column:1/-1}.field label{font-size:10px;color:var(--muted)}.field input,.field select{width:100%;border:1px solid var(--line);border-radius:9px;padding:10px;background:var(--surface2);color:var(--text);outline:none}.field input:focus,.field select:focus{border-color:var(--accent)}.modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:17px}.helper{color:var(--muted);font-size:10px;line-height:1.55;margin-top:10px}.error-message{color:var(--bad);font-size:11px;min-height:17px;margin-top:8px}.auth-wrap{min-height:100vh;display:grid;place-items:center;padding:20px}.auth-card{width:min(430px,100%);background:var(--surface);border:1px solid var(--line);border-radius:20px;padding:30px;box-shadow:var(--shadow)}.auth-card h1{font-size:24px;margin:21px 0 5px;letter-spacing:-.04em}.auth-card>p{color:var(--muted);font-size:12px;margin:0 0 23px}.auth-card .field{margin:11px 0}.auth-card .button{width:100%;margin-top:10px;padding:11px}.login-note{font-size:10px;color:var(--muted);margin-top:16px}.toast{position:fixed;bottom:18px;left:50%;transform:translate(-50%,15px);opacity:0;transition:.2s;z-index:50;background:var(--text);color:var(--bg);padding:10px 14px;border-radius:9px;font-size:11px;pointer-events:none}.toast.show{opacity:1;transform:translate(-50%,0)}.grid-footer{color:var(--muted);font-size:10px;text-align:center;margin:21px 0}.hidden{display:none!important}
@media(max-width:1050px){.shell{grid-template-columns:72px 1fr}.sidebar{padding:20px 10px}.brand{justify-content:center;padding:0}.brand strong,.nav-title,.nav button span:not(.nav-icon),.sidebar-foot{display:none}.nav button{justify-content:center;padding:12px 4px}.main{padding:24px 20px}.widget{grid-column:span 6}.widget.wide{grid-column:span 12}}
@media(max-width:680px){.shell{display:block}.sidebar{position:fixed;z-index:4;bottom:0;left:0;right:0;height:57px;border-right:0;border-top:1px solid var(--line);padding:5px 10px;background:var(--surface);display:block}.brand,.nav-title{display:none}.nav{display:flex;justify-content:space-around}.nav button{flex:1;display:grid;gap:2px;padding:5px 1px;font-size:9px;text-align:center}.nav button span:not(.nav-icon){display:block!important;font-size:8px}.nav-icon{font-size:15px}.main{padding:19px 13px 78px}.topbar{align-items:flex-start}.page-title{font-size:22px}.top-actions{gap:5px}.top-actions .status-pill{display:none}.overview{grid-template-columns:1fr 1fr;gap:8px}.stat{min-height:99px;padding:12px}.stat-value{font-size:22px}.dashboard{gap:9px}.widget,.widget.wide,.widget.full{grid-column:1/-1}.core-grid{grid-template-columns:repeat(4,1fr)}.section-head{margin-top:20px}.form-grid{grid-template-columns:1fr}.field.full{grid-column:auto}.data-table{font-size:9px}.data-table td,.data-table th{padding:7px 4px}}

.language-select{max-width:112px;background:var(--surface);border:1px solid var(--line);border-radius:9px;padding:8px 9px;color:var(--text);font-size:11px;min-height:39px}.auth-tools{display:flex;justify-content:flex-end;margin:-12px 0 16px}.host-panel{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:15px 17px;margin:0 0 18px;box-shadow:0 8px 26px rgba(0,0,0,.04)}.host-panel-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:11px}.host-panel-head h2{font-size:13px;margin:0}.host-panel-head p{font-size:9px;color:var(--muted);letter-spacing:.12em;margin:3px 0 0}.host-info-card .info-grid{grid-template-columns:repeat(4,minmax(0,1fr));gap:13px 18px}.host-info-card .info-item:last-child{grid-column:1/-1!important}.panel-actions{display:flex;gap:7px}.history-select{min-width:76px}.history-custom{min-width:30px;padding:5px 7px}.widget-tools{flex-wrap:wrap}.select-mini:focus-visible,.language-select:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media(max-width:1050px){.host-info-card .info-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:680px){.sidebar{height:calc(57px + env(safe-area-inset-bottom));padding:5px 10px calc(5px + env(safe-area-inset-bottom))}.main{padding-bottom:calc(78px + env(safe-area-inset-bottom));align-self:start}.topbar{gap:8px}.top-actions{flex-wrap:wrap;justify-content:flex-end}.language-select{min-height:35px;padding:6px 5px;max-width:94px;font-size:10px}.host-panel{padding:13px}.host-info-card .info-grid{grid-template-columns:1fr 1fr;gap:10px}.section-head{align-items:flex-start}.section-head .panel-actions{flex-direction:column}.history-select{min-width:66px}}

.mini-chart{cursor:crosshair;touch-action:pan-y}.mini-chart:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}.chart-hover{fill:var(--text);stroke:var(--accent);stroke-width:2;pointer-events:none}.chart-tooltip{position:fixed;display:none;white-space:pre-line;pointer-events:none;z-index:60;max-width:min(340px,calc(100vw - 24px));padding:9px 11px;border:1px solid var(--line);border-radius:9px;background:var(--surface);color:var(--text);box-shadow:var(--shadow);font-size:11px;line-height:1.55}.chart-tooltip.visible{display:block}
.mini-chart{height:148px}.mini-chart .chart-grid{stroke:var(--grid);stroke-width:.7}.mini-chart .chart-grid-vertical{stroke-dasharray:2 4}.mini-chart .chart-axis{stroke:var(--muted);stroke-width:1}.mini-chart .chart-label{fill:var(--muted);font:8px ui-sans-serif,system-ui,sans-serif}.mini-chart .chart-axis-caption{fill:var(--muted);font:7px ui-sans-serif,system-ui,sans-serif}.mini-chart .chart-gap-mark{stroke:var(--warn);stroke-width:1;stroke-dasharray:2 4;opacity:.8;pointer-events:none}.mini-chart .chart-crosshair{stroke:var(--accent2);stroke-width:1;stroke-dasharray:3 3;pointer-events:none;opacity:.85}
@media(max-width:420px){.mini-chart .chart-label{font-size:7px}.mini-chart .chart-label-middle,.mini-chart .chart-grid-middle{display:none}}
.chart-empty{height:148px}.status-pill.stale .dot{background:var(--warn);box-shadow:0 0 10px var(--warn)}
</style></head><body><div id="app"></div><div id="toast" class="toast"></div><div id="chart-tooltip" class="chart-tooltip" role="tooltip"></div>
<script>
const app=document.getElementById('app');
const LANGUAGE_NAMES = { en: 'English', zh: '中文', ja: '日本語', fr: 'Français', ru: 'Русский', de: 'Deutsch' };
const LANGUAGE_INDEX = { en: 1, zh: 0, ja: 2, fr: 3, ru: 4, de: 5 };
const LANGUAGE_LOCALE = { en: 'en-US', zh: 'zh-CN', ja: 'ja-JP', fr: 'fr-FR', ru: 'ru-RU', de: 'de-DE' };
const CHART_GAP_SECONDS = 90; // Allow scheduling jitter around the one-minute history sample interval.
const TRANSLATION_ROWS = [
  ['总览','Overview','概要','Vue générale','Обзор','Übersicht'],
  ['网络资产','Assets','ネットワーク資産','Équipements réseau','Сетевые узлы','Netzwerkgeräte'],
  ['进程','Processes','プロセス','Processus','Процессы','Prozesse'],
  ['事件与 DNS','Events & DNS','イベントと DNS','Événements et DNS','События и DNS','Ereignisse & DNS'],
  ['系统总览','System overview','システム概要','Vue du système','Обзор системы','Systemübersicht'],
  ['进程监控','Process monitor','プロセス監視','Surveillance des processus','Монитор процессов','Prozessüberwachung'],
  ['LIVE INFRASTRUCTURE','LIVE INFRASTRUCTURE','ライブインフラストラクチャ','INFRASTRUCTURE EN DIRECT','МОНИТОРИНГ ИНФРАСТРУКТУРЫ','LIVE-INFRASTRUKTUR'],
  ['实时采集','Live collection','リアルタイム収集','Collecte en direct','Сбор данных','Live-Erfassung'],
  ['切换主题','Switch theme','テーマを切り替え','Changer de thème','Сменить тему','Darstellung wechseln'],
  ['退出登录','Sign out','ログアウト','Déconnexion','Выйти','Abmelden'],
  ['等待主机数据…','Waiting for host data…','ホストデータを待っています…','En attente des données de l’hôte…','Ожидание данных узла…','Warte auf Hostdaten…'],
  ['本地监控代理已就绪','Local agent ready','ローカルエージェント稼働中','Agent local prêt','Локальный агент готов','Lokaler Agent bereit'],
  ['纯标准库 · 单文件运行','Standard library · single file','標準ライブラリ · 単一ファイル','Bibliothèque standard · fichier unique','Стандартная библиотека · один файл','Standardbibliothek · einzelne Datei'],
  ['自定义监控面板','Custom monitoring dashboard','カスタム監視ダッシュボード','Tableau de bord personnalisé','Настраиваемая панель мониторинга','Individuelles Monitoring-Dashboard'],
  ['拖拽卡片调整布局 · 数据每 2.5 秒更新','Drag cards to rearrange · refreshes every 2.5 seconds','カードをドラッグして並べ替え · 2.5 秒ごとに更新','Glissez les cartes pour les réorganiser · actualisation toutes les 2,5 s','Перетаскивайте карточки · обновление каждые 2,5 с','Karten zum Neuordnen ziehen · Aktualisierung alle 2,5 Sekunden'],
  ['管理资产','Manage assets','資産を管理','Gérer les équipements','Управление узлами','Geräte verwalten'],
  ['＋ 添加监控','＋ Add monitor','＋ 監視を追加','＋ Ajouter un indicateur','＋ Добавить монитор','＋ Monitoring hinzufügen'],
  ['CPU 使用率','CPU utilization','CPU 使用率','Utilisation CPU','Загрузка CPU','CPU-Auslastung'],
  ['每核心采样正常','Per-core sampling active','コア別サンプリング中','Mesure par cœur active','Данные по каждому ядру','Messung je Kern aktiv'],
  ['聚合采样','Aggregate CPU sample','CPU 全体のサンプル','Mesure CPU globale','Общая загрузка CPU','CPU-Gesamtmessung'],
  ['当前系统未公开 CPU 计数','CPU counters are unavailable on this system','このシステムでは CPU カウンターを取得できません','Les compteurs CPU ne sont pas disponibles sur ce système','Счётчики CPU недоступны в этой системе','CPU-Zähler sind auf diesem System nicht verfügbar'],
  ['内存使用','Memory usage','メモリ使用量','Utilisation mémoire','Использование памяти','Speichernutzung'],
  ['网络资产','Network assets','ネットワーク資産','Équipements réseau','Сетевые узлы','Netzwerkgeräte'],
  ['在线','Online','オンライン','En ligne','В сети','Online'],
  ['含本地节点与已配置资产','Local host and configured assets','ローカルホストと設定済み資産','Hôte local et équipements configurés','Локальный хост и настроенные узлы','Lokaler Host und konfigurierte Geräte'],
  ['系统运行时长','Uptime','稼働時間','Disponibilité','Время работы','Betriebszeit'],
  ['处理器','Processor','プロセッサ','Processeur','Процессор','Prozessor'],
  ['内存','Memory','メモリ','Mémoire','Память','Speicher'],
  ['网络流量','Network traffic','ネットワーク通信量','Trafic réseau','Сетевой трафик','Netzwerkverkehr'],
  ['磁盘','Disk','ディスク','Disque','Диск','Datenträger'],
  ['系统负载','System load','システム負荷','Charge système','Нагрузка системы','Systemlast'],
  ['登录事件','Login events','ログインイベント','Connexions','Входы','Anmeldeereignisse'],
  ['DNS 缓存','DNS cache','DNS キャッシュ','Cache DNS','DNS-кэш','DNS-Cache'],
  ['主机信息','Host information','ホスト情報','Informations sur l’hôte','Информация о хосте','Hostinformationen'],
  ['↓ 下载','↓ Download','↓ 受信','↓ Réception','↓ Входящий','↓ Download'],
  ['↑ 上传','↑ Upload','↑ 送信','↑ Envoi','↑ Исходящий','↑ Upload'],
  ['全部网卡','All interfaces','すべての NIC','Toutes les interfaces','Все интерфейсы','Alle Schnittstellen'],
  ['可用','Available','空き','Disponible','Доступно','Verfügbar'],
  ['已用','used','使用済み','utilisé','использовано','belegt'],
  ['分区详情','Partition details','パーティション詳細','Détails des partitions','Разделы диска','Partitionsdetails'],
  ['1 分钟','1 min','1 分','1 min','1 мин','1 Min.'],
  ['5 分钟','5 min','5 分','5 min','5 мин','5 Min.'],
  ['15 分钟','15 min','15 分','15 min','15 мин','15 Min.'],
  ['负载平均值','Load average','ロードアベレージ','Charge moyenne','Средняя нагрузка','Durchschnittslast'],
  ['Windows 不提供 Unix load average；此处显示 CPU 使用率参考值。','Windows does not expose Unix load averages; CPU utilization is shown as a reference.','Windows は Unix の load average を公開しません。参考値として CPU 使用率を表示します。','Windows ne fournit pas la charge Unix ; l’utilisation CPU est affichée à titre indicatif.','Windows не предоставляет Unix load average; показана справочная загрузка CPU.','Windows stellt keinen Unix-Load-Average bereit; hier dient die CPU-Auslastung als Richtwert.'],
  ['网络 ↓ / ↑','Network ↓ / ↑','ネットワーク ↓ / ↑','Réseau ↓ / ↑','Сеть ↓ / ↑','Netzwerk ↓ / ↑'],
  ['进程网络连接数来自系统套接字；标准库无法读取每个进程的网络字节速率。','Per-process socket counts are shown where available; portable byte rates are not exposed by the standard library.','プロセスごとのソケット数を表示します。標準ライブラリではプロセス別の通信量を取得できません。','Le nombre de sockets est affiché si disponible ; la bibliothèque standard ne fournit pas les débits par processus.','Показывается число сокетов, если доступно; стандартная библиотека не предоставляет скорости по процессам.','Verfügbare Socket-Anzahlen werden gezeigt; die Standardbibliothek liefert keine Prozess-Netzwerkraten.'],
  ['当前没有可读取的 SSH / RDP 登录事件。日志可能需要更高权限或相应服务。','No readable SSH / RDP sign-in events were found. Logs may require additional permissions or services.','読み取り可能な SSH / RDP ログインイベントがありません。追加権限またはサービスが必要な場合があります。','Aucun événement SSH / RDP lisible. Des droits supplémentaires ou services peuvent être nécessaires.','Нет доступных событий SSH / RDP. Могут потребоваться права или соответствующие службы.','Keine lesbaren SSH- / RDP-Anmeldungen. Eventuell sind zusätzliche Rechte oder Dienste nötig.'],
  ['按系统日志权限读取 SSH、RDP（3389）和远程登录事件。','SSH, RDP (3389) and remote sign-in events depend on system logs and permissions.','SSH、RDP（3389）、リモートログインの情報はシステムログと権限に依存します。','Les événements SSH, RDP (3389) et distants dépendent des journaux système et des droits.','События SSH, RDP (3389) и удалённого входа зависят от журналов и прав.','SSH-, RDP- (3389) und Remote-Anmeldungen hängen von Systemprotokollen und Berechtigungen ab.'],
  ['条目','entries','件','entrées','записей','Einträge'],
  ['来源：','Source: ','ソース: ','Source : ','Источник: ','Quelle: '],
  ['系统未公开 DNS 缓存详情。','This system does not expose DNS cache details.','このシステムは DNS キャッシュの詳細を公開していません。','Ce système ne publie pas les détails de son cache DNS.','Система не предоставляет сведения о DNS-кэше.','Dieses System stellt keine DNS-Cache-Details bereit.'],
  ['主机名','Hostname','ホスト名','Nom d’hôte','Имя хоста','Hostname'],
  ['系统版本','System version','システムバージョン','Version du système','Версия системы','Systemversion'],
  ['内核版本','Kernel version','カーネルバージョン','Version du noyau','Версия ядра','Kernelversion'],
  ['物理内存','Physical memory','物理メモリ','Mémoire physique','Физическая память','Physischer Speicher'],
  ['当前会话','Current sessions','現在のセッション','Sessions actuelles','Текущие сеансы','Aktuelle Sitzungen'],
  ['无活动终端会话或当前账户无读取权限','No active terminal sessions or access is restricted','アクティブな端末セッションがないか、アクセスが制限されています','Aucune session active ou accès restreint','Нет активных сеансов или доступ ограничен','Keine aktiven Sitzungen oder Zugriff eingeschränkt'],
  ['本机采样','Local sample','ローカルサンプル','Échantillon local','Локальный сбор','Lokale Messung'],
  ['远程节点','remote nodes','リモートノード','nœuds distants','удалённых узлов','entfernte Knoten'],
  ['分区详情','Partition details','パーティション詳細','Détails des partitions','Разделы диска','Partitionsdetails'],
  ['挂载点','Mount point','マウントポイント','Point de montage','Точка монтирования','Einhängepunkt'],
  ['设备','Device','デバイス','Périphérique','Устройство','Gerät'],
  ['文件系统','Filesystem','ファイルシステム','Système de fichiers','Файловая система','Dateisystem'],
  ['已用 / 总量','Used / total','使用済み / 合計','Utilisé / total','Использовано / всего','Belegt / gesamt'],
  ['添加监控卡片','Add monitor card','監視カードを追加','Ajouter une carte','Добавить карточку монитора','Monitoring-Karte hinzufügen'],
  ['网络资产','Network asset','ネットワーク資産','Équipement réseau','Сетевой узел','Netzwerkgerät'],
  ['监控项目','Monitor item','監視項目','Indicateur','Показатель','Messwert'],
  ['添加卡片','Add card','カードを追加','Ajouter la carte','Добавить карточку','Karte hinzufügen'],
  ['取消','Cancel','キャンセル','Annuler','Отмена','Abbrechen'],
  ['最多添加 32 张卡片','You can add up to 32 cards','カードは最大 32 枚まで追加できます','Vous pouvez ajouter jusqu’à 32 cartes','Можно добавить не более 32 карточек','Es können höchstens 32 Karten hinzugefügt werden'],
  ['配置远程 TinyWatch 节点。每个节点需在“代理令牌”处填入目标主机生成的令牌。','Configure remote TinyWatch nodes. Enter the token generated by the target host.','リモート TinyWatch ノードを設定します。対象ホストが発行したトークンを入力してください。','Configurez un nœud TinyWatch distant avec le jeton généré par l’hôte cible.','Настройте удалённый узел TinyWatch с токеном целевого хоста.','Richten Sie entfernte TinyWatch-Knoten mit dem Token des Zielhosts ein.'],
  ['资产名称','Asset name','資産名','Nom de l’équipement','Имя узла','Gerätename'],
  ['服务地址','Service URL','サービス URL','URL du service','URL сервиса','Dienst-URL'],
  ['代理令牌','Agent token','エージェントトークン','Jeton de l’agent','Токен агента','Agent-Token'],
  ['例如：edge-node-01','For example: edge-node-01','例: edge-node-01','Exemple : edge-node-01','Например: edge-node-01','Zum Beispiel: edge-node-01'],
  ['在目标节点设置页复制代理令牌','Paste the token from the target node settings','対象ノードの設定からトークンを貼り付け','Collez le jeton des paramètres du nœud cible','Вставьте токен из настроек целевого узла','Token aus den Einstellungen des Zielknotens einfügen'],
  ['本机代理令牌（复制到其他节点的资产配置中）：','This host’s agent token (copy it to the remote asset settings):','このホストのトークン（リモートノードの設定にコピー）:','Jeton de cet hôte (à copier dans la configuration distante) :','Токен этого хоста (скопируйте в настройки удалённого узла):','Token dieses Hosts (in die entfernte Gerätekonfiguration kopieren):'],
  ['建立管理员密码','Create administrator password','管理者パスワードを設定','Définir le mot de passe administrateur','Задать пароль администратора','Administratorpasswort festlegen'],
  ['首次使用，请设置用于此控制台的密码。','First use: create a password for this console.','初回利用時に、このコンソールのパスワードを作成してください。','Première utilisation : créez un mot de passe pour cette console.','Первый запуск: создайте пароль для этой консоли.','Erste Verwendung: Passwort für diese Konsole erstellen.'],
  ['欢迎回来','Welcome back','おかえりなさい','Bon retour','С возвращением','Willkommen zurück'],
  ['登录后查看主机与网络资产指标。','Sign in to view host and network asset metrics.','ログインしてホストとネットワーク資産の指標を表示します。','Connectez-vous pour consulter les métriques des hôtes et équipements réseau.','Войдите, чтобы просматривать показатели хостов и сетевых узлов.','Melden Sie sich an, um Host- und Netzwerkmetriken anzuzeigen.'],
  ['管理员密码','Administrator password','管理者パスワード','Mot de passe administrateur','Пароль администратора','Administratorpasswort'],
  ['确认密码','Confirm password','パスワードの確認','Confirmer le mot de passe','Подтвердите пароль','Passwort bestätigen'],
  ['至少 10 个字符','At least 10 characters','10 文字以上','10 caractères minimum','Не менее 10 символов','Mindestens 10 Zeichen'],
  ['再次输入密码','Enter the password again','パスワードをもう一度入力','Saisissez à nouveau le mot de passe','Введите пароль ещё раз','Passwort erneut eingeben'],
  ['设置密码并继续','Set password and continue','パスワードを設定して続行','Définir le mot de passe et continuer','Задать пароль и продолжить','Passwort festlegen und fortfahren'],
  ['登录控制台','Sign in','ログイン','Se connecter','Войти','Anmelden'],
  ['密码使用 PBKDF2-SHA256 加盐存储在本机 JSON 数据库中。','The password is stored locally in the JSON database using salted PBKDF2-SHA256.','パスワードはソルト付き PBKDF2-SHA256 でローカル JSON データベースに保存されます。','Le mot de passe est stocké localement dans la base JSON avec PBKDF2-SHA256 salé.','Пароль хранится локально в JSON-базе с солью PBKDF2-SHA256.','Das Passwort wird lokal mit gesalzenem PBKDF2-SHA256 in der JSON-Datenbank gespeichert.'],
  ['两次输入的密码不一致','The passwords do not match','パスワードが一致しません','Les mots de passe ne correspondent pas','Пароли не совпадают','Die Passwörter stimmen nicht überein'],
  ['TinyWatch 无法启动','TinyWatch could not start','TinyWatch を起動できません','TinyWatch n’a pas pu démarrer','Не удалось запустить TinyWatch','TinyWatch konnte nicht gestartet werden'],
  ['输入密码','Enter password','パスワードを入力','Saisissez le mot de passe','Введите пароль','Passwort eingeben'],
  ['监控','Monitor','監視','Surveillance','Монитор','Monitoring'],
  ['节点暂不可用，检查资产地址、网络和代理令牌。','Node unavailable. Check its address, network and agent token.','ノードを利用できません。アドレス、ネットワーク、トークンを確認してください。','Nœud indisponible. Vérifiez l’adresse, le réseau et le jeton.','Узел недоступен. Проверьте адрес, сеть и токен агента.','Knoten nicht verfügbar. Adresse, Netzwerk und Agent-Token prüfen.'],
  ['离线 · ','Offline · ','オフライン · ','Hors ligne · ','Не в сети · ','Offline · '],
  ['无法连接','Connection failed','接続できません','Connexion impossible','Не удалось подключиться','Verbindung fehlgeschlagen'],
  ['未选择有效监控项','No valid monitor selected','有効な監視項目が選択されていません','Aucun indicateur valide sélectionné','Не выбран допустимый показатель','Kein gültiger Messwert ausgewählt'],
  ['移除卡片','Remove card','カードを削除','Supprimer la carte','Удалить карточку','Karte entfernen'],
  ['% utilization','% utilization','% 使用率','% d’utilisation','% загрузки','% Auslastung'],
  ['逻辑核心实时占用','Live utilization per logical core','論理コア別のリアルタイム使用率','Utilisation en direct par cœur logique','Текущая загрузка каждого ядра','Live-Auslastung je logischem Kern'],
  ['聚合 CPU 计数','Aggregate CPU counters','CPU 全体カウンター','Compteurs CPU agrégés','Общие счётчики CPU','CPU-Gesamtzähler'],
  ['当前平台未提供兼容的 CPU 计数接口','No compatible CPU counter is available on this platform','このプラットフォームでは互換性のある CPU カウンターを利用できません','Aucun compteur CPU compatible sur cette plateforme','На этой платформе нет совместимого счётчика CPU','Auf dieser Plattform ist kein kompatibler CPU-Zähler verfügbar'],
  ['逻辑核心','logical cores','論理コア','cœurs logiques','логических ядер','logische Kerne'],
  ['累计接收','Received total','累計受信','Total reçu','Получено всего','Empfangen gesamt'],
  ['发送','Sent','送信','Envoyé','Отправлено','Gesendet'],
  ['% used','% used','% 使用','% utilisé','% занято','% belegt'],
  ['已用 ','Used ','使用済み ','Utilisé ','Использовано ','Belegt '],
  ['个逻辑核心','logical cores','論理コア','cœurs logiques','логических ядер','logische Kerne'],
  ['Linux 在存在 ss 命令且有权限时显示 TCP 收发速率；其他平台显示进程套接字数（若可读取）。标准库接口不提供跨平台的逐进程网络字节计数。','Linux shows TCP rates when ss is available and permissions allow it. Other platforms show socket counts when readable. The standard library has no portable per-process byte counters.','Linux では ss と権限があれば TCP 通信速度を表示します。他の OS では取得可能な場合にソケット数を表示します。標準ライブラリには移植可能なプロセス別通信量 API がありません。','Linux affiche les débits TCP si ss et les droits sont disponibles. Les autres systèmes affichent le nombre de sockets si lisible. La bibliothèque standard ne fournit pas de compteurs réseau par processus portables.','Linux показывает скорость TCP при наличии ss и прав. Другие системы показывают число сокетов, если оно доступно. Стандартная библиотека не предоставляет переносимые счётчики трафика по процессам.','Linux zeigt TCP-Raten, wenn ss und Berechtigungen verfügbar sind. Andere Systeme zeigen lesbare Socket-Anzahlen. Die Standardbibliothek bietet keine plattformübergreifenden Byte-Zähler je Prozess.'],
  ['未能读取进程信息，可能需要提升服务权限。','Unable to read process data. The service may need elevated permissions.','プロセス情報を読み取れません。サービスに追加権限が必要な場合があります。','Impossible de lire les processus. Le service peut nécessiter des droits élevés.','Не удалось прочитать процессы. Службе могут потребоваться дополнительные права.','Prozessdaten nicht lesbar. Der Dienst benötigt möglicherweise erhöhte Rechte.'],
  ['按系统日志权限读取 SSH、RDP（3389）和远程登录事件。','SSH, RDP (3389) and remote sign-in events depend on system log permissions.','SSH、RDP（3389）、リモートログインの表示はシステムログの権限に依存します。','Les événements SSH, RDP (3389) et distants dépendent des droits sur les journaux système.','События SSH, RDP (3389) и удалённого входа зависят от прав чтения системных журналов.','SSH-, RDP- (3389) und Remote-Anmeldungen hängen von den Rechten für Systemprotokolle ab.'],
  ['系统 DNS 缓存','system DNS cache','システム DNS キャッシュ','cache DNS système','системный DNS-кэш','System-DNS-Cache'],
  ['无活动终端会话或当前账户无读取权限','No active terminal sessions or read permission','アクティブな端末セッションがないか、読み取り権限がありません','Aucune session active ou droit de lecture manquant','Нет активных сеансов или прав на чтение','Keine aktiven Sitzungen oder Leserechte'],
  ['系统未公开 DNS 缓存详情。','The system does not expose DNS cache details.','システムは DNS キャッシュの詳細を公開していません。','Le système ne fournit pas les détails du cache DNS.','Система не предоставляет сведения о DNS-кэше.','Das System stellt keine DNS-Cache-Details bereit.'],
  ['主机信息','Host information','ホスト情報','Informations sur l’hôte','Информация о хосте','Hostinformationen'],
  ['当前会话','Current session','現在のセッション','Session actuelle','Текущий сеанс','Aktuelle Sitzung'],
  ['系统总览','System overview','システム概要','Vue du système','Обзор системы','Systemübersicht'],
  ['查看运行进程及资源占用。','View running processes and resource usage.','実行中のプロセスとリソース使用量を表示します。','Consultez les processus actifs et leur utilisation des ressources.','Просмотр работающих процессов и использования ресурсов.','Laufende Prozesse und Ressourcennutzung anzeigen.'],
  ['SSH / RDP 登录事件与系统 DNS 缓存。','SSH / RDP sign-in events and system DNS cache.','SSH / RDP ログインイベントとシステム DNS キャッシュ。','Connexions SSH / RDP et cache DNS système.','События входа SSH / RDP и системный DNS-кэш.','SSH- / RDP-Anmeldungen und System-DNS-Cache.'],
  ['1 小时','1 hour','1 時間','1 heure','1 час','1 Stunde'],
  ['6 小时','6 hours','6 時間','6 heures','6 часов','6 Stunden'],
  ['24 小时','24 hours','24 時間','24 heures','24 часа','24 Stunden'],
  ['7 天','7 days','7 日','7 jours','7 дней','7 Tage'],
  ['历史数据','History','履歴','Historique','История','Verlauf'],
  ['暂无历史样本','No historical samples yet','履歴データはまだありません','Aucun échantillon historique','Исторических данных пока нет','Noch keine Verlaufsdaten'],
  ['本地采样每分钟保存一次，保留 7 天。','Local samples are saved every minute and retained for 7 days.','ローカルデータは毎分保存され、7 日間保持されます。','Les données locales sont enregistrées chaque minute et conservées 7 jours.','Локальные данные сохраняются раз в минуту и хранятся 7 дней.','Lokale Messwerte werden minütlich gespeichert und 7 Tage aufbewahrt.'],
  ['自定义监控面板','Custom monitoring dashboard','カスタム監視ダッシュボード','Tableau de bord personnalisé','Настраиваемая панель мониторинга','Individuelles Monitoring-Dashboard'],
  ['拖拽卡片调整布局 · 数据每 2.5 秒更新','Drag cards to rearrange · refreshes every 2.5 seconds','カードをドラッグして並べ替え · 2.5 秒ごとに更新','Glissez les cartes pour les réorganiser · actualisation toutes les 2,5 s','Перетаскивайте карточки · обновление каждые 2,5 с','Karten zum Neuordnen ziehen · Aktualisierung alle 2,5 Sekunden'],
  ['查看各主机的登录事件与 DNS 缓存。','View sign-in events and DNS caches for each host.','各ホストのログインイベントと DNS キャッシュを表示します。','Consultez les connexions et le cache DNS de chaque hôte.','Просмотр входов и DNS-кэша для каждого хоста.','Anmeldungen und DNS-Caches je Host anzeigen.'],
  ['本机采样 · ','Local sample · ','ローカルサンプル · ','Échantillon local · ','Локальный сбор · ','Lokale Messung · '],
  [' · 远程节点 ',' · remote nodes ',' · リモートノード ',' · nœuds distants ',' · удалённых узлов ',' · entfernte Knoten '],
  [' 在线',' online',' オンライン',' en ligne',' в сети',' online'],
  ['正在连接监控节点…','Connecting to monitoring nodes…','監視ノードに接続中…','Connexion aux nœuds de surveillance…','Подключение к узлам мониторинга…','Verbindung zu Monitoring-Knoten…'],
  ['网络资产已添加','Network asset added','ネットワーク資産を追加しました','Équipement réseau ajouté','Сетевой узел добавлен','Netzwerkgerät hinzugefügt'],
  ['资产已移除','Asset removed','ネットワーク資産を削除しました','Équipement supprimé','Сетевой узел удалён','Netzwerkgerät entfernt'],
  ['当前系统未公开 CPU 计数','CPU counters are unavailable on this system','このシステムでは CPU カウンターを取得できません','Les compteurs CPU ne sont pas disponibles sur ce système','Счётчики CPU недоступны в этой системе','CPU-Zähler sind auf diesem System nicht verfügbar'],
  ['全部网卡','All interfaces','すべてのインターフェース','Toutes les interfaces','Все интерфейсы','Alle Schnittstellen'],
  ['仅支持 1 小时、6 小时、24 小时或 7 天范围。','Choose 1 hour, 6 hours, 24 hours, or 7 days.','1 時間、6 時間、24 時間、7 日から選択してください。','Choisissez 1 heure, 6 heures, 24 heures ou 7 jours.','Выберите период: 1 час, 6 часов, 24 часа или 7 дней.','Wählen Sie 1 Stunde, 6 Stunden, 24 Stunden oder 7 Tage.'],
];
TRANSLATION_ROWS.push(
  ['本机','Local host','ローカルホスト','Hôte local','Локальный хост','Lokaler Host'],
  ['本地节点','Local node','ローカルノード','Nœud local','Локальный узел','Lokaler Knoten'],
  ['HOST PROFILE','HOST PROFILE','ホスト情報','PROFIL DE L’HÔTE','ПРОФИЛЬ ХОСТА','HOSTPROFIL'],
  ['Network interface','Network interface','ネットワークインターフェース','Interface réseau','Сетевой интерфейс','Netzwerkschnittstelle'],
  ['Historical time range','Historical time range','履歴の期間','Période historique','Период истории','Zeitraum des Verlaufs'],
  ['共 ','Total ','合計 ','Total ','Всего ','Gesamt '],
  [' 核',' cores',' コア',' cœurs',' ядра',' Kerne'],
  ['添加资产','Add asset','資産を追加','Ajouter un équipement','Добавить узел','Gerät hinzufügen'],
  ['移除','Remove','削除','Supprimer','Удалить','Entfernen'],
  ['磁盘与分区','Disks and partitions','ディスクとパーティション','Disques et partitions','Диски и разделы','Datenträger und Partitionen'],
  ['使用率','Usage','使用率','Utilisation','Использование','Auslastung'],
  ['Language','Language','言語','Langue','Язык','Sprache'],
  ['自定义时间段','Custom range','カスタム期間','Plage personnalisée','Пользовательский период','Benutzerdefinierter Zeitraum'],
  ['自定义历史时间段','Custom history range','履歴の期間を指定','Plage historique personnalisée','Выбрать период истории','Benutzerdefinierter Verlaufszeitraum'],
  ['开始日期和时间','Start date and time','開始日時','Date et heure de début','Дата и время начала','Startdatum und -uhrzeit'],
  ['结束日期和时间','End date and time','終了日時','Date et heure de fin','Дата и время окончания','Enddatum und -uhrzeit'],
  ['选择日期和时间','Choose date and time','日時を選択','Choisir la date et l’heure','Выбрать дату и время','Datum und Uhrzeit wählen'],
  ['应用时间段','Apply range','期間を適用','Appliquer la période','Применить период','Zeitraum anwenden'],
  ['历史数据仅保留最近 7 天，请选择有效范围','History is retained for the last 7 days. Choose a valid range.','履歴は直近 7 日間のみ保存されます。有効な範囲を選択してください。','L’historique est conservé pendant 7 jours. Choisissez une période valide.','История хранится за последние 7 дней. Выберите допустимый период.','Der Verlauf wird 7 Tage aufbewahrt. Wählen Sie einen gültigen Zeitraum.'],
  ['起始时间必须早于结束时间，且结束时间不能在未来','The start must be before the end, and the end cannot be in the future.','開始は終了より前にし、終了に未来の日時は指定できません。','Le début doit précéder la fin, qui ne peut pas être dans le futur.','Начало должно быть раньше окончания, а окончание не может быть в будущем.','Der Start muss vor dem Ende liegen; das Ende darf nicht in der Zukunft liegen.'],
  ['自定义历史查询需要有效的起止时间','Custom history queries need valid start and end times.','カスタム履歴には有効な開始・終了時刻が必要です。','Une plage personnalisée exige des dates valides.','Для периода нужны корректные даты начала и окончания.','Für einen benutzerdefinierten Verlauf sind gültige Start- und Endzeiten erforderlich.'],
  ['资产','Assets','資産','Actifs','Активы','Assets'],
  ['设置','Settings','設定','Paramètres','Настройки','Einstellungen'],
  ['配置语言、外观和历史数据保留期限。','Configure language, appearance, and data retention.','言語、外観、履歴データの保存期間を設定します。','Configurez la langue, l’apparence et la conservation des données.','Настройте язык, внешний вид и срок хранения данных.','Sprache, Darstellung und Datenspeicherung konfigurieren.'],
  ['外观','Appearance','外観','Apparence','Внешний вид','Darstellung'],
  ['主题','Theme','テーマ','Thème','Тема','Design'],
  ['深色','Dark','ダーク','Sombre','Тёмная','Dunkel'],
  ['浅色','Light','ライト','Clair','Светлая','Hell'],
  ['数据保留期限','Data retention','データ保持期間','Rétention des données','Срок хранения данных','Datenspeicherung'],
  ['保留时间','Retention period','保存期間','Durée de conservation','Срок хранения','Aufbewahrungsdauer'],
  ['历史样本每分钟保存到本地 JSON 数据库。','Historical samples are saved to the local JSON database every minute.','履歴データは毎分ローカル JSON データベースに保存されます。','Les échantillons sont enregistrés chaque minute dans la base JSON locale.','Исторические данные сохраняются в локальную JSON-базу каждую минуту.','Verlaufsdaten werden jede Minute in der lokalen JSON-Datenbank gespeichert.'],
  ['缩短保留期限会立即删除超出期限的旧数据。','Shortening retention immediately deletes older data outside the selected period.','保存期間を短縮すると、期間外の古いデータは直ちに削除されます。','Une réduction de la durée supprime immédiatement les anciennes données hors période.','При сокращении срока старые данные за его пределами удаляются сразу.','Eine kürzere Aufbewahrungsdauer löscht ältere Daten außerhalb des Zeitraums sofort.'],
  ['保存设置','Save settings','設定を保存','Enregistrer les paramètres','Сохранить настройки','Einstellungen speichern'],
  ['设置已保存','Settings saved','設定を保存しました','Paramètres enregistrés','Настройки сохранены','Einstellungen gespeichert'],
  ['1 天','1 day','1 日','1 jour','1 день','1 Tag'],
  ['3 天','3 days','3 日','3 jours','3 дня','3 Tage'],
  ['14 天','14 days','14 日','14 jours','14 дней','14 Tage'],
  ['30 天','30 days','30 日','30 jours','30 дней','30 Tage'],
  ['历史数据保留最近','History retained for the last','履歴データの保存期間は直近','Historique conservé sur les','История хранится за последние','Verlauf wird für die letzten'],
  ['所选时间超出当前数据保留期限','The selected range exceeds the current data retention period.','選択した期間は現在のデータ保持期間を超えています。','La période sélectionnée dépasse la durée de conservation actuelle.','Выбранный период выходит за текущий срок хранения данных.','Der ausgewählte Zeitraum überschreitet die aktuelle Aufbewahrungsdauer.'],
  ['数据更新失败','Update failed','データ更新に失敗','Échec de la mise à jour','Не удалось обновить данные','Datenaktualisierung fehlgeschlagen'],
  ['数据延迟','Data delayed','データ遅延','Données en retard','Задержка данных','Daten verzögert'],
  ['刚刚','just now','たった今','à l’instant','только что','gerade eben'],
  ['秒前','seconds ago','秒前','secondes','с назад','Sekunden zuvor'],
  ['数据接收','Data received','データ受信','Données reçues','Данные получены','Daten empfangen'],
  ['最近一次请求失败，TinyWatch 会继续重试','The latest request failed. TinyWatch will keep retrying.','直近のリクエストに失敗しました。TinyWatch は再試行を続けます。','La dernière requête a échoué. TinyWatch va réessayer.','Последний запрос завершился ошибкой. TinyWatch продолжит попытки.','Die letzte Anfrage ist fehlgeschlagen. TinyWatch versucht es weiter.'],
  ['数据时间以浏览器本地时区显示','Data times use the browser local time zone.','データ時刻はブラウザーのローカルタイムゾーンで表示します。','Les heures utilisent le fuseau horaire local du navigateur.','Время отображается в часовом поясе браузера.','Zeitangaben verwenden die lokale Zeitzone des Browsers.'],
  ['数据库已从备份恢复，请检查设置','Database restored from backup. Review your settings.','データベースをバックアップから復元しました。設定を確認してください。','Base restaurée depuis la sauvegarde. Vérifiez les paramètres.','База восстановлена из резервной копии. Проверьте настройки.','Datenbank aus Sicherung wiederhergestellt. Einstellungen prüfen.'],
  ['本地时间','Local time','現地時間','Heure locale','Местное время','Ortszeit'],
  ['历史图表：横轴为本地时间，纵轴为指标数值。可用左右方向键查看采样点。','History chart: local time on the horizontal axis and metric values on the vertical axis. Use the arrow keys to inspect samples.','履歴グラフ：横軸は現地時間、縦軸は指標値です。左右の矢印キーでサンプルを確認できます。','Graphique historique : heure locale en abscisse, valeur en ordonnée. Utilisez les flèches pour parcourir les mesures.','График истории: местное время по горизонтали, значение метрики по вертикали. Стрелками можно просматривать точки.','Verlauf: Ortszeit auf der waagerechten, Messwerte auf der senkrechten Achse. Mit den Pfeiltasten Messpunkte prüfen.'],
  ['HTTPS required','HTTPS required','HTTPS が必要','HTTPS requis','Требуется HTTPS','HTTPS erforderlich'],
  ['远程节点必须使用有效的 HTTPS 证书；HTTP 仅适用于本机 localhost 或回环地址。','Remote nodes require a valid HTTPS certificate. HTTP is limited to localhost or loopback addresses.','リモートノードには有効な HTTPS 証明書が必要です。HTTP は localhost またはループバックアドレスに限ります。','Les nœuds distants exigent un certificat HTTPS valide. HTTP est réservé à localhost ou aux adresses de bouclage.','Для удалённых узлов требуется действительный сертификат HTTPS. HTTP разрешён только для localhost или loopback.','Entfernte Knoten benötigen ein gültiges HTTPS-Zertifikat. HTTP ist auf localhost oder Loopback-Adressen beschränkt.'],
  ['远程资产必须使用 HTTPS；HTTP 仅限 localhost / 回环地址','Remote assets must use HTTPS; HTTP is allowed only for localhost / loopback addresses','リモート資産は HTTPS が必要です。HTTP は localhost / ループバックに限ります','Les équipements distants doivent utiliser HTTPS ; HTTP est réservé à localhost / loopback','Удалённые ресурсы должны использовать HTTPS; HTTP разрешён только для localhost / loopback','Entfernte Assets müssen HTTPS verwenden; HTTP ist nur für localhost / Loopback zulässig']
);
const LANGUAGE_LOOKUP = new Map();
for (const row of TRANSLATION_ROWS) LANGUAGE_LOOKUP.set(row[0], row);
const TRANSLATION_KEYS = [...LANGUAGE_LOOKUP.keys()].sort((a, b) => b.length - a.length);

function readPreference(key, fallback) {
  try { return localStorage.getItem(key) || fallback; } catch (error) { return fallback; }
}
function tr(value) {
  let text = String(value == null ? '' : value);
  const index = LANGUAGE_INDEX[state.language] ?? 1;
  if (index === 0) return text;
  for (const source of TRANSLATION_KEYS) {
    if (text.includes(source)) text = text.split(source).join(LANGUAGE_LOOKUP.get(source)[index]);
  }
  return text;
}
function localizeDOM(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) node.nodeValue = tr(node.nodeValue);
  root.querySelectorAll('[title],[placeholder],[aria-label]').forEach((element) => {
    for (const attribute of ['title', 'placeholder', 'aria-label']) {
      if (element.hasAttribute(attribute)) element.setAttribute(attribute, tr(element.getAttribute(attribute)));
    }
  });
}
function languageSelector() {
  return '<select class="language-select" id="language-select" aria-label="Language">' +
    Object.entries(LANGUAGE_NAMES).map(([code, name]) => '<option value="' + code + '" ' +
      (state.language === code ? 'selected' : '') + '>' + name + '</option>').join('') + '</select>';
}
function bindLanguageSelector() {
  const select = document.getElementById('language-select');
  if (!select) return;
  select.onchange = () => {
    const password = document.getElementById('password');
    const password2 = document.getElementById('password2');
    const savedPassword = password ? password.value : '';
    const savedPassword2 = password2 ? password2.value : '';
    state.language = LANGUAGE_NAMES[select.value] ? select.value : 'en';
    try { localStorage.setItem('tinywatch.language', state.language); } catch (error) { /* private mode */ }
    document.documentElement.lang = state.language;
    if (state.authenticated) render();
    else {
      authScreen(state.setup);
      const nextPassword = document.getElementById('password');
      const nextPassword2 = document.getElementById('password2');
      if (nextPassword) nextPassword.value = savedPassword;
      if (nextPassword2) nextPassword2.value = savedPassword2;
    }
  };
}

const state={authenticated:false,setup:false,config:null,data:null,history:{},historical:{},historyPending:{},historyRanges:{},historyCustom:{},chartData:{},chartSequence:0,timer:null,freshnessTimer:null,lastRefreshAt:0,refreshFailed:false,dragged:null,modal:null,view:'overview',language:LANGUAGE_NAMES[readPreference('tinywatch.language','en')]?readPreference('tinywatch.language','en'):'en'};
document.documentElement.lang=state.language;
const metrics={cpu:['处理器','◉'],memory:['内存','▤'],network:['网络流量','↕'],disk:['磁盘','▣'],load:['系统负载','⌁'],processes:['进程','▥'],logins:['登录事件','⌑'],dns:['DNS 缓存','⌘'],info:['主机信息','◈']};
const fmtBytes=n=>{n=Number(n)||0;const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{minimumFractionDigits:i?1:0,maximumFractionDigits:i?1:0}).format(i===0?Math.round(n):n)+' '+u[i]};
const pct=n=>Math.max(0,Math.min(100,Number(n)||0));
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,method='GET',body){const r=await fetch(path,{method,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined,credentials:'same-origin'});let j={};try{j=await r.json()}catch(e){}if(!r.ok){const error=new Error(j.error||('HTTP '+r.status));error.status=r.status;throw error}return j}
function toast(text){const el=document.getElementById('toast');el.textContent=tr(text);el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2200)}
function setTheme(theme){document.documentElement.dataset.theme=theme||'dark'}
function authScreen(isSetup){
  state.setup=isSetup;
  app.innerHTML='<div class="auth-wrap"><section class="auth-card"><div class="auth-tools">'+languageSelector()+'</div><div class="brand" style="padding:0"><div class="brand-mark">◈</div><div><strong>TinyWatch</strong><small>INFRASTRUCTURE CONSOLE</small></div></div><h1>'+(isSetup?'建立管理员密码':'欢迎回来')+'</h1><p>'+(isSetup?'首次使用，请设置用于此控制台的密码。':'登录后查看主机与网络资产指标。')+'</p><form id="auth-form"><div class="field"><label>管理员密码</label><input id="password" type="password" autocomplete="'+(isSetup?'new-password':'current-password')+'" required minlength="'+(isSetup?'10':'1')+'" autofocus placeholder="'+(isSetup?'至少 10 个字符':'输入密码')+'"></div>'+(isSetup?'<div class="field"><label>确认密码</label><input id="password2" type="password" autocomplete="new-password" required minlength="10" placeholder="再次输入密码"></div>':'')+'<div id="auth-error" class="error-message"></div><button class="button primary" type="submit">'+(isSetup?'设置密码并继续':'登录控制台')+'</button></form><div class="login-note">密码使用 PBKDF2-SHA256 加盐存储在本机 JSON 数据库中。</div></section></div>';
  document.documentElement.lang=state.language;
  localizeDOM(app);
  bindLanguageSelector();
  document.getElementById('auth-form').onsubmit=async e=>{e.preventDefault();const p=document.getElementById('password').value;try{if(isSetup&&p!==document.getElementById('password2').value)throw new Error('两次输入的密码不一致');await api(isSetup?'/api/setup':'/api/login','POST',{password:p});await enterApp()}catch(err){document.getElementById('auth-error').textContent=tr(err.message)}};
}
async function boot(){
  try{const status=await api('/api/status');if(status.authenticated)await enterApp();else authScreen(status.setup_required)}
  catch(error){app.innerHTML='<div class="auth-wrap"><div class="auth-card"><div class="auth-tools">'+languageSelector()+'</div><h1>TinyWatch 无法启动</h1><p>'+esc(error.message)+'</p></div></div>';localizeDOM(app);bindLanguageSelector()}
}
async function enterApp(){
  state.authenticated=true;
  try{state.config=await api('/api/config');setTheme(state.config.theme);render();if(state.config.storage_recovered)toast('数据库已从备份恢复，请检查设置');await refresh();startPolling()}
  catch(error){state.authenticated=false;authScreen(false)}
}
function startPolling(){
  clearTimeout(state.timer);
  clearInterval(state.freshnessTimer);
  state.freshnessTimer=setInterval(updateFreshnessIndicator,1000);
  const poll=async()=>{await refresh();if(state.authenticated)state.timer=setTimeout(poll,2500)};
  poll();
}
function updateFreshnessIndicator(){
  const status=document.getElementById('live-status'),label=document.getElementById('live-status-label'),footer=document.getElementById('updated-at');
  if(!status||!label)return;
  const age=state.lastRefreshAt?Math.max(0,Math.floor((Date.now()-state.lastRefreshAt)/1000)):null;
  const stale=state.refreshFailed||age===null||age>=10;
  label.textContent=tr(state.refreshFailed?'数据更新失败':(stale?'数据延迟':'实时采集'));
  status.classList.toggle('stale',stale);
  status.title=tr(state.refreshFailed?'最近一次请求失败，TinyWatch 会继续重试':'数据时间以浏览器本地时区显示');
  if(footer&&age!==null){
    const ageText=age<3?tr('刚刚'):new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US').format(age)+' '+tr('秒前');
    footer.dataset.freshness=tr('数据接收')+' · '+ageText;
    const summary=footer.dataset.summary||footer.textContent;
    footer.dataset.summary=summary;
    footer.textContent=summary+' · '+footer.dataset.freshness;
  }
}
async function refresh(){
  if(!state.authenticated)return;
  try{
    const data=await api('/api/metrics');state.data=data;state.lastRefreshAt=Date.now();state.refreshFailed=false;
    for(const [id,node] of Object.entries(data.nodes||{})){
      if(!node.online||!node.metrics)continue;
      const metric=node.metrics;pushHistory(id+':cpu',metric.cpu.percent);
      pushHistory(id+':memory',metric.memory.percent);pushHistory(id+':disk',metric.disk.percent);
      pushHistory(id+':load',metric.load&&metric.load.length?metric.load[0]:0);
      const interfaces=metric.network.interfaces||[];
      pushHistory(id+':network:total',metric.network.rx_rate+metric.network.tx_rate);
      for(const item of interfaces)pushHistory(id+':network:'+item.name,item.rx_rate+item.tx_rate);
    }
    draw();
  }catch(error){
    if(error.status===401){state.authenticated=false;clearTimeout(state.timer);clearInterval(state.freshnessTimer);authScreen(false)}
    else{state.refreshFailed=true;updateFreshnessIndicator()}
  }
}
function pushHistory(key,value){const values=state.history[key]||(state.history[key]=[]);values.push([Date.now()/1000,Number(value)||0]);if(values.length>36)values.shift()}
function nodeFor(id){return state.data&&state.data.nodes&&state.data.nodes[id]}
function render(){
  if(!state.config)return;
  app.innerHTML='<div class="shell"><aside class="sidebar"><div class="brand"><div class="brand-mark">◈</div><div><strong>TinyWatch</strong><small>INFRASTRUCTURE</small></div></div><nav class="nav" aria-label="Main navigation"><button class="active" data-view="overview"><span class="nav-icon">⌂</span><span>总览</span></button><button data-menu="assets"><span class="nav-icon">⌘</span><span>资产</span></button><button data-menu="settings"><span class="nav-icon">⚙</span><span>设置</span></button></nav></aside><main class="main"><header class="topbar"><div><div class="eyebrow">LIVE INFRASTRUCTURE</div><h1 class="page-title" id="page-title">系统总览</h1></div><div class="top-actions">'+languageSelector()+'<span class="status-pill" id="live-status"><i class="dot"></i><span id="live-status-label">实时采集</span></span><button class="icon-button" id="theme-toggle" title="切换主题" aria-label="Switch theme">◐</button><button class="icon-button" id="logout-button" title="退出登录" aria-label="Sign out">↗</button></div></header><section class="host-panel"><div class="host-panel-head"><div><h2>主机信息</h2><p>本地节点 · HOST PROFILE</p></div></div><div id="host-summary"></div></section><section class="overview" id="overview"></section><div class="section-head"><div><h2 id="panel-title">自定义监控面板</h2><p id="panel-description">拖拽卡片调整布局 · 数据每 2.5 秒更新</p></div><div class="panel-actions" id="panel-actions"><button class="button subtle" id="assets-manage">管理资产</button><button class="button primary" id="add-widget">＋ 添加监控</button></div></div><section class="dashboard" id="dashboard" aria-live="polite"></section><div class="grid-footer" id="updated-at">正在连接监控节点…</div></main></div><div id="modal" class="modal-backdrop"></div>';
  document.documentElement.lang=state.language;localizeDOM(app);bindLanguageSelector();
  document.getElementById('theme-toggle').onclick=toggleTheme;
  document.getElementById('logout-button').onclick=logout;
  document.getElementById('assets-manage').onclick=showAssets;
  document.getElementById('add-widget').onclick=showAddWidget;
  document.querySelectorAll('.nav button').forEach(button=>{
    if(button.dataset.view){button.onclick=()=>switchView(button.dataset.view);button.classList.toggle('active',button.dataset.view===state.view)}
    else button.onclick=()=>{document.querySelectorAll('.nav button').forEach(item=>item.classList.toggle('active',item===button));if(button.dataset.menu==='assets')showAssets();else showSettings()}
  });
  document.getElementById('page-title').textContent=tr('系统总览');
  draw();
}
async function toggleTheme(){state.config.theme=state.config.theme==='dark'?'light':'dark';setTheme(state.config.theme);try{await saveConfig()}catch(error){toast(error.message)}}
async function logout(){clearTimeout(state.timer);clearInterval(state.freshnessTimer);try{await api('/api/logout','POST',{})}catch(error){}state.authenticated=false;authScreen(false)}
function switchView(view){
  state.view='overview';
  document.querySelectorAll('.nav button').forEach(button=>button.classList.toggle('active',button.dataset.view===state.view));
  document.getElementById('page-title').textContent=tr('系统总览');
  window.scrollTo({top:0,behavior:'smooth'});
  draw();
}
function draw(){
  if(!state.data||!state.config)return;
  const activeChart=document.activeElement&&document.activeElement.matches('.mini-chart')?document.activeElement:null;
  const activeWidget=activeChart&&activeChart.closest('.widget');
  const focusRestore=activeChart?{widget:activeWidget&&activeWidget.dataset.widget,index:activeChart.dataset.activeIndex||'0'}:null;
  state.chartData={};state.chartSequence=0;
  const local=nodeFor('local');if(!local||!local.metrics)return;
  const metricsLocal=local.metrics;const alive=Object.values(state.data.nodes).filter(node=>node.online).length;const total=Object.keys(state.data.nodes).length;
  const overview=document.getElementById('overview');const dashboard=document.getElementById('dashboard');
  const summary=document.getElementById('host-summary');
  summary.innerHTML='<article class="host-info-card">'+infoCard(metricsLocal)+'</article>';localizeDOM(summary);
  overview.classList.remove('hidden');
  document.getElementById('panel-actions').classList.remove('hidden');
  document.getElementById('panel-title').textContent=tr('自定义监控面板');
  document.getElementById('panel-description').textContent=tr('拖拽卡片调整布局 · 数据每 2.5 秒更新');
  document.getElementById('side-host')?.remove();
  overview.innerHTML='<article class="stat"><div class="stat-label">CPU 使用率 <span class="tag good">'+metricsLocal.cpu.logical_cores+' 核</span></div><div class="stat-value">'+(metricsLocal.cpu.available?metricsLocal.cpu.percent:'—')+'<small>'+(metricsLocal.cpu.available?'%':'')+'</small></div><div class="stat-foot">'+(metricsLocal.cpu.cores.length?'每核心采样正常':(metricsLocal.cpu.available?'聚合采样':'当前系统未公开 CPU 计数'))+'</div></article><article class="stat"><div class="stat-label">内存使用 <span>RAM</span></div><div class="stat-value">'+fmtBytes(metricsLocal.memory.used)+'</div><div class="stat-foot">共 '+fmtBytes(metricsLocal.memory.total)+' · '+metricsLocal.memory.percent+'%</div></article><article class="stat"><div class="stat-label">网络资产 <span class="tag good">在线</span></div><div class="stat-value">'+alive+'<small> / '+total+'</small></div><div class="stat-foot">含本地节点与已配置资产</div></article><article class="stat"><div class="stat-label">系统运行时长 <span>UPTIME</span></div><div class="stat-value" style="font-size:22px">'+esc(metricsLocal.info.uptime)+'</div><div class="stat-foot">'+esc(metricsLocal.info.os)+' '+esc(metricsLocal.info.release)+'</div></article>';
  localizeDOM(overview);
  const assets=[{id:'local',name:metricsLocal.info.hostname}].concat(state.config.assets||[]);
  const widgets=(state.config.widgets||[]).filter(widget=>widget.metric!=='info');
  dashboard.innerHTML='';
  for(const widget of widgets){
    const node=nodeFor(widget.node);const asset=assets.find(item=>item.id===widget.node)||{id:widget.node,name:widget.node};
    const card=document.createElement('article');card.className='widget '+(['processes','logins','dns'].includes(widget.metric)?'wide':'');
    card.draggable=!widget.transient;card.dataset.widget=widget.id;card.innerHTML=widgetCard(widget,node,asset);dashboard.appendChild(card);localizeDOM(card);bindWidget(card,widget);
  }
  if(focusRestore&&focusRestore.widget){
    const card=Array.from(dashboard.children).find(item=>item.dataset.widget===focusRestore.widget);
    const chart=card&&card.querySelector('.mini-chart');
    if(chart){chart.dataset.activeIndex=focusRestore.index;chart.focus({preventScroll:true})}
  }
  dashboard.ondragover=event=>{event.preventDefault();const target=event.target.closest('.widget');if(target&&state.dragged&&target!==state.dragged)target.classList.add('drag-over')};
  dashboard.ondragleave=event=>{const target=event.target.closest('.widget');if(target)target.classList.remove('drag-over')};
  dashboard.ondrop=event=>{event.preventDefault();const target=event.target.closest('.widget');if(!target||!state.dragged||target===state.dragged)return;target.classList.remove('drag-over');const cards=Array.from(dashboard.children);const from=cards.indexOf(state.dragged),to=cards.indexOf(target);if(from<to)target.after(state.dragged);else target.before(state.dragged);state.config.widgets=Array.from(dashboard.children).map(card=>state.config.widgets.find(widget=>widget.id===card.dataset.widget)).filter(Boolean);saveConfig().catch(error=>toast(error.message))};
  const footer=document.getElementById('updated-at');footer.dataset.summary=tr('本机采样 · ')+new Date(metricsLocal.sampled_at).toLocaleString(LANGUAGE_LOCALE[state.language]||'en-US')+tr(' · 远程节点 ')+alive+'/'+total+tr(' 在线');
  footer.textContent=footer.dataset.summary;updateFreshnessIndicator();
}
function widgetCard(widget,node,asset){
  const title=metrics[widget.metric]||['监控','◈'];let content='';
  if(!node)content='<div class="asset-error">节点暂不可用，检查资产地址、网络和代理令牌。</div>';
  else if(!node.online)content='<div class="asset-error">离线 · '+esc(node.error||'无法连接')+'</div>';
  else{
    const metric=node.metrics;
    switch(widget.metric){
      case'cpu':content=cpuCard(metric,widget.node);break;case'memory':content=memoryCard(metric.memory,widget.node);break;
      case'network':content=networkCard(metric,widget);break;case'disk':content=diskCard(metric,widget);break;
      case'load':content=loadCard(metric,widget.node);break;case'processes':content=processCard(metric);break;
      case'logins':content=loginCard(metric);break;case'dns':content=dnsCard(metric);break;
      case'info':content=infoCard(metric);break;default:content='<div class="empty">未选择有效监控项</div>';
    }
  }
  const tools=(widget.metric==='network'&&node&&node.metrics?interfaceSelector(node.metrics.network,widget.node):'')+
    (historySelector(widget,node))+
    (widget.metric==='disk'&&node&&node.metrics?'<button class="select-mini" data-disk="'+esc(widget.node)+'">分区详情</button>':'')+
    (!widget.transient?'<button class="remove-widget" title="移除卡片" aria-label="Remove card">×</button>':'');
  return '<header class="widget-head"><div class="widget-title"><i>'+title[1]+'</i><div>'+title[0]+'<div class="widget-node">'+esc(asset.name)+'</div></div></div><div class="widget-tools">'+tools+'</div></header>'+content;
}
function cpuCard(metric,node){
  const cores=metric.cpu.cores||[];let bars='';
  for(const core of cores.slice(0,24))bars+='<div class="core"><label><span>'+esc(core.name.replace('cpu',''))+'</span><span>'+core.percent+'%</span></label><div class="track"><span style="width:'+pct(core.percent)+'%"></span></div></div>';
  const history=historyChartData(node,'cpu','');
  return '<div class="big-value">'+(metric.cpu.available?metric.cpu.percent:'—')+'<small>'+(metric.cpu.available?'% utilization':'')+'</small></div><div class="metric-sub">'+(cores.length?'逻辑核心实时占用':(metric.cpu.available?'聚合 CPU 计数':'当前平台未提供兼容的 CPU 计数接口'))+'</div>'+sparkline(history,'cpu')+(bars?'<div class="core-grid">'+bars+'</div>':'');
}
function memoryCard(memory,node){
  const history=historyChartData(node,'memory','');
  return '<div class="big-value">'+fmtBytes(memory.used)+'<small> / '+fmtBytes(memory.total)+'</small></div><div class="metric-sub">可用 '+fmtBytes(memory.available)+' · '+memory.percent+'%</div><div class="track" style="height:8px;margin-top:16px"><span style="width:'+pct(memory.percent)+'%"></span></div>'+sparkline(history,'memory');
}
function interfaceSelector(network,node){
  const items=network.interfaces||[];const selected=state.history[node+':iface']||'';
  return '<select class="select-mini iface-select" data-node="'+esc(node)+'" aria-label="Network interface"><option value="">全部网卡</option>'+items.map(item=>'<option value="'+esc(item.name)+'" '+(selected===item.name?'selected':'')+'>'+esc(item.name)+'</option>').join('')+'</select>';
}
function networkCard(metric,widget){
  const interfaces=metric.network.interfaces||[];const selected=state.history[widget.node+':iface'];const item=interfaces.find(entry=>entry.name===selected);
  const rx=item?item.rx_rate:metric.network.rx_rate;const tx=item?item.tx_rate:metric.network.tx_rate;
  const history=historyChartData(widget.node,'network',selected||'');
  return '<div class="duo"><div class="duo-box"><label>↓ 下载</label><strong>'+fmtBytes(rx)+'/s</strong></div><div class="duo-box"><label>↑ 上传</label><strong>'+fmtBytes(tx)+'/s</strong></div></div><div class="metric-sub" style="margin-top:9px">累计接收 '+fmtBytes(item?item.rx_total:interfaces.reduce((sum,entry)=>sum+entry.rx_total,0))+' · 发送 '+fmtBytes(item?item.tx_total:interfaces.reduce((sum,entry)=>sum+entry.tx_total,0))+'</div>'+sparkline(history,'network');
}
function diskCard(metric,widget){
  const disk=metric.disk;const top=(disk.partitions||[]).slice(0,3);const history=historyChartData(widget.node,'disk','');
  return '<div class="big-value">'+disk.percent+'<small>% used</small></div><div class="metric-sub">已用 '+fmtBytes(disk.used)+' / '+fmtBytes(disk.total)+'</div><div class="track" style="height:7px;margin:12px 0 5px"><span style="width:'+pct(disk.percent)+'%"></span></div>'+top.map(item=>'<div class="disk-line"><span>'+esc(item.mount)+'</span><b>'+fmtBytes(item.used)+' / '+fmtBytes(item.total)+'</b></div>').join('')+sparkline(history,'disk');
}
function loadCard(metric,node){
  const load=metric.load||[];const history=historyChartData(node,'load','');
  if(metric.info.os==='Windows')return '<div class="big-value">'+Math.round((Number(load[0])||0)*100)+'<small>%</small></div><div class="metric-sub">Windows 不提供 Unix load average；此处显示 CPU 使用率参考值。</div>'+sparkline(history,'load');
  const labels=['1 分钟','5 分钟','15 分钟'];
  return '<div class="duo">'+labels.slice(0,Math.max(1,load.length)).map((label,index)=>'<div class="duo-box"><label>'+label+'</label><strong>'+Number(load[index]||0).toFixed(2)+'</strong></div>').join('')+'</div><div class="metric-sub" style="margin-top:10px">负载平均值 · '+metric.cpu.logical_cores+' 个逻辑核心</div>'+sparkline(history,'load');
}
function historySelectionKey(node,metric,iface){return node+'|'+metric+'|'+(iface||'')}
function historyCacheKey(node,metric,range,iface,custom){
  const selected=custom||state.historyCustom[historySelectionKey(node,metric,iface)];
  const suffix=range==='custom'&&selected?'|'+selected.start+'|'+selected.end:range;
  return historySelectionKey(node,metric,iface)+'|'+suffix;
}
function historySelector(widget,node){
  if(!node||!node.online||!['cpu','memory','disk','network','load'].includes(widget.metric))return '';
  const iface=widget.metric==='network'?(state.history[widget.node+':iface']||''):'';
  const selection=historySelectionKey(widget.node,widget.metric,iface);
  const range=state.historyRanges[selection]||'1h';
  const custom=state.historyCustom[selection];
  const retentionDays=Number(state.config.history_retention_days)||7;
  const ranges=[['1h','1 小时',3600],['6h','6 小时',21600],['24h','24 小时',86400],['3d','3 天',259200],['7d','7 天',604800],['14d','14 天',1209600],['30d','30 天',2592000]];
  const options=ranges.filter(item=>item[2]<=retentionDays*86400).map(item=>'<option value="'+item[0]+'" '+(range===item[0]?'selected':'')+'>'+item[1]+'</option>').join('');
  requestHistory(widget.node,widget.metric,range,iface,custom);
  return '<select class="select-mini history-select" data-node="'+esc(widget.node)+'" data-metric="'+widget.metric+'" data-interface="'+esc(iface)+'" aria-label="Historical time range">'+options+'<option value="custom" '+(range==='custom'?'selected':'')+'>自定义时间段</option></select><button type="button" class="select-mini history-custom" data-node="'+esc(widget.node)+'" data-metric="'+widget.metric+'" data-interface="'+esc(iface)+'" title="选择日期和时间" aria-label="Choose date and time">◷</button>';
}
function requestHistory(node,metric,range,iface,custom){
  if(range==='custom'&&!custom)return;
  const key=historyCacheKey(node,metric,range,iface,custom);const cached=state.historical[key];
  if(state.historyPending[key]||(cached&&Date.now()-cached.fetchedAt<60000))return;
  state.historyPending[key]=true;
  const query=new URLSearchParams({node,metric,range});if(iface)query.set('iface',iface);
  if(range==='custom'){query.set('start',String(custom.start));query.set('end',String(custom.end))}
  api('/api/history?'+query.toString()).then(result=>{state.historical[key]={points:result.points||[],fetchedAt:Date.now()};draw()})
    .catch(error=>{if(error.status===401){state.authenticated=false;authScreen(false)}else toast(error.message)})
    .finally(()=>{delete state.historyPending[key]});
}
function historyChartData(node,metric,iface){
  const selection=historySelectionKey(node,metric,iface);const range=state.historyRanges[selection]||'1h';
  const cached=state.historical[historyCacheKey(node,metric,range,iface,state.historyCustom[selection])];
  if(cached){
    const index={cpu:1,memory:3,disk:3,load:1};
    return cached.points.map(point=>({timestamp:Number(point[0]),value:metric==='network'?Number(point[1]||0)+Number(point[2]||0):Number(point[index[metric]]||0),rx:Number(point[1]||0),tx:Number(point[2]||0)})).filter(point=>Number.isFinite(point.timestamp)&&Number.isFinite(point.value));
  }
  const key=metric==='network'?node+':network:'+(iface||'total'):node+':'+metric;
  return (state.history[key]||[]).map(point=>({timestamp:Number(point[0]),value:Number(point[1])})).filter(point=>Number.isFinite(point.timestamp)&&Number.isFinite(point.value));
}
function localDateTimeValue(date){
  const pad=value=>String(value).padStart(2,'0');
  return date.getFullYear()+'-'+pad(date.getMonth()+1)+'-'+pad(date.getDate())+'T'+pad(date.getHours())+':'+pad(date.getMinutes());
}
function showHistoryRange(node,metric,iface){
  const selection=historySelectionKey(node,metric,iface);const existing=state.historyCustom[selection];
  const now=new Date();now.setSeconds(0,0);
  const end=existing?new Date(existing.end*1000):now;
  const start=existing?new Date(existing.start*1000):new Date(end.getTime()-60*60*1000);
  const retentionDays=Number(state.config.history_retention_days)||7;
  const minimum=localDateTimeValue(new Date(Date.now()-retentionDays*24*60*60*1000));
  const maximum=localDateTimeValue(now);
  const dayLabels=['天','days','日','jours','дней','Tage'];const daySuffix=dayLabels[LANGUAGE_INDEX[state.language]||1];
  const punctuation=state.language==='zh'||state.language==='ja'?'。':'.';
  const rangeHint=tr('历史数据保留最近')+' '+retentionDays+' '+daySuffix+punctuation;
  modal('<header class="modal-head"><div><h3>自定义历史时间段</h3><div class="helper">'+rangeHint+'</div></div><button class="close" data-close aria-label="Close">×</button></header><form id="history-range-form"><div class="form-grid"><div class="field"><label for="history-start">开始日期和时间</label><input id="history-start" type="datetime-local" step="60" min="'+minimum+'" max="'+maximum+'" value="'+localDateTimeValue(start)+'" required></div><div class="field"><label for="history-end">结束日期和时间</label><input id="history-end" type="datetime-local" step="60" min="'+minimum+'" max="'+maximum+'" value="'+localDateTimeValue(end)+'" required></div></div><div class="error-message" id="history-range-error"></div><div class="modal-actions"><button type="button" class="button subtle" data-close>取消</button><button type="submit" class="button primary">应用时间段</button></div></form>');
  const startInput=document.getElementById('history-start');const endInput=document.getElementById('history-end');
  startInput.onchange=()=>{endInput.min=startInput.value};
  document.getElementById('history-range-form').onsubmit=event=>{
    event.preventDefault();const startSeconds=new Date(startInput.value).getTime()/1000;const endSeconds=new Date(endInput.value).getTime()/1000;
    const error=document.getElementById('history-range-error');
    if(!Number.isFinite(startSeconds)||!Number.isFinite(endSeconds)||startSeconds>=endSeconds){error.textContent=tr('起始时间必须早于结束时间，且结束时间不能在未来');return}
    const currentSeconds=Date.now()/1000;
    const retentionSeconds=retentionDays*24*60*60;
    if(startSeconds<currentSeconds-retentionSeconds||endSeconds>currentSeconds){error.textContent=tr('所选时间超出当前数据保留期限');return}
    state.historyCustom[selection]={start:startSeconds,end:endSeconds};state.historyRanges[selection]='custom';closeModal();draw();
  };
}

function processCard(m){const rows=(m.processes||[]).slice(0,8);return rows.length?'<div style="overflow:auto"><table class="data-table"><thead><tr><th>进程</th><th>PID</th><th>CPU</th><th>内存</th><th>网络 ↓ / ↑</th></tr></thead><tbody>'+rows.map(p=>'<tr><td title="'+esc(p.name)+'">'+esc(p.name)+'</td><td>'+p.pid+'</td><td>'+p.cpu+'%</td><td>'+fmtBytes(p.memory)+'</td><td>'+(p.network_supported?fmtBytes(p.network_rx_rate||0)+'/s · '+fmtBytes(p.network_tx_rate||0)+'/s':(p.network_connections==null?'—':p.network_connections+' sockets'))+'</td></tr>').join('')+'</tbody></table></div><div class="notice">Linux 在存在 ss 命令且有权限时显示 TCP 收发速率；其他平台显示进程套接字数（若可读取）。标准库接口不提供跨平台的逐进程网络字节计数。</div>':'<div class="empty">未能读取进程信息，可能需要提升服务权限。</div>'}
function loginCard(m){const rows=(m.logins||[]).slice(0,7);return rows.length?'<div>'+rows.map(x=>'<div class="disk-line"><span class="tag '+(/accepted|opened|success|4624/i.test(x.message)?'good':'bad')+'">'+esc(x.kind)+'</span><span style="flex:1;margin-left:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="'+esc(x.message)+'">'+esc(x.message)+'</span></div>').join('')+'</div><div class="notice">按系统日志权限读取 SSH、RDP（3389）和远程登录事件。</div>':'<div class="empty">当前没有可读取的 SSH / RDP 登录事件。日志可能需要更高权限或相应服务。</div>'}
function dnsCard(m){const rows=(m.dns.entries||[]).slice(0,6);return '<div class="big-value">'+(m.dns.count||0)+'<small> 条目</small></div><div class="metric-sub">来源：'+esc(m.dns.source||'系统 DNS 缓存')+'</div>'+(rows.length?rows.map(x=>'<div class="disk-line"><span>'+esc(x.name)+'</span><span>'+esc(x.value||x.type||'')+'</span></div>').join(''):'<div class="empty">系统未公开 DNS 缓存详情。</div>')}
function infoCard(m){const x=m.info;return '<div class="info-grid"><div class="info-item"><label>主机名</label><strong>'+esc(x.hostname)+'</strong></div><div class="info-item"><label>处理器</label><strong>'+esc(x.cpu)+' · '+x.logical_cores+' 核</strong></div><div class="info-item"><label>系统版本</label><strong>'+esc(x.system)+'</strong></div><div class="info-item"><label>内核版本</label><strong>'+esc(x.release)+' · '+esc(x.architecture)+'</strong></div><div class="info-item"><label>物理内存</label><strong>'+fmtBytes(x.memory_total)+'</strong></div><div class="info-item"><label>系统运行时长</label><strong>'+esc(x.uptime)+'</strong></div><div class="info-item" style="grid-column:1/-1"><label>当前会话</label><strong>'+esc((x.sessions||[]).join(' · ')||'无活动终端会话或当前账户无读取权限')+'</strong></div></div>'}
function chartAxisMaximum(value){
  const rawStep=Math.max(value,0.000001)/4;
  const magnitude=Math.pow(10,Math.floor(Math.log10(rawStep)));
  const fraction=rawStep/magnitude;
  const niceFraction=fraction<=1?1:fraction<=2?2:fraction<=5?5:10;
  return niceFraction*magnitude*4;
}
function downsampleHistory(samples,maximumPoints){
  const ordered=samples.slice().filter(point=>Number.isFinite(Number(point.timestamp))&&Number.isFinite(Number(point.value)))
    .sort((left,right)=>Number(left.timestamp)-Number(right.timestamp));
  if(ordered.length<=maximumPoints)return ordered;
  const gapPairs=[];
  for(let index=1;index<ordered.length;index++){
    if(Number(ordered[index].timestamp)-Number(ordered[index-1].timestamp)>CHART_GAP_SECONDS)gapPairs.push([index-1,index]);
  }
  const maxGapPairs=Math.floor((maximumPoints-2)/2);
  const gapStride=Math.max(1,Math.ceil(gapPairs.length/maxGapPairs));
  const selected=new Set([0,ordered.length-1]);
  gapPairs.forEach((pair,index)=>{if(index%gapStride===0){selected.add(pair[0]);selected.add(pair[1])}});
  const candidates=[];
  for(let index=1;index<ordered.length-1;index++)if(!selected.has(index))candidates.push(index);
  const remaining=maximumPoints-selected.size;
  const bucketCount=Math.floor(remaining/2);
  for(let bucket=0;bucket<bucketCount;bucket++){
    const start=Math.floor(bucket*candidates.length/bucketCount);
    const end=Math.max(start+1,Math.floor((bucket+1)*candidates.length/bucketCount));
    if(start>=candidates.length)break;
    let minimum=candidates[start],maximum=minimum;
    for(let offset=start+1;offset<Math.min(end,candidates.length);offset++){
      const candidate=candidates[offset];
      if(Number(ordered[candidate].value)<Number(ordered[minimum].value))minimum=candidate;
      if(Number(ordered[candidate].value)>Number(ordered[maximum].value))maximum=candidate;
    }
    selected.add(minimum);selected.add(maximum);
  }
  return [...selected].sort((left,right)=>left-right).map(index=>ordered[index]);
}
function chartTimeLabel(timestamp,span,includeYear){
  const date=new Date(timestamp*1000);
  if(!Number.isFinite(date.getTime()))return '—';
  const locale=LANGUAGE_LOCALE[state.language]||'en-US';
  return span<86400
    ?date.toLocaleTimeString(locale,{hour:'2-digit',minute:'2-digit'})
    :date.toLocaleDateString(locale,includeYear?{year:'2-digit',month:'2-digit',day:'2-digit'}:{month:'2-digit',day:'2-digit'});
}
function sparkline(samples,metric){
  if(!samples||!samples.length)return '<div class="chart-empty">'+tr('暂无历史样本')+'</div>';
  const maximumPoints=240;let points=downsampleHistory(samples,maximumPoints);
  if(!points.length)return '<div class="chart-empty">'+tr('暂无历史样本')+'</div>';
  const width=320,height=148,plotLeft=74,plotRight=314,plotTop=9,plotBottom=101;
  const plotWidth=plotRight-plotLeft,plotHeight=plotBottom-plotTop;
  const values=points.map(point=>Math.max(0,Number(point.value)||0));
  const percentageMetric=['cpu','memory','disk'].includes(metric);
  const axisMaximum=percentageMetric?100:chartAxisMaximum(Math.max(metric==='network'?4:1,...values));
  const timestamps=points.map(point=>Number(point.timestamp));
  const hasTimeRange=timestamps.length>1&&timestamps.every(Number.isFinite)&&timestamps[timestamps.length-1]>timestamps[0];
  const firstTime=hasTimeRange?timestamps[0]:0;
  const timeSpan=hasTimeRange?timestamps[timestamps.length-1]-firstTime:0;
  const firstDate=new Date(timestamps[0]*1000),lastDate=new Date(timestamps[timestamps.length-1]*1000);
  const crossesYear=Number.isFinite(firstDate.getTime())&&Number.isFinite(lastDate.getTime())&&firstDate.getFullYear()!==lastDate.getFullYear();
  const pointCount=points.length;
  points=points.map((point,index)=>{
    const value=Math.max(0,Number(point.value)||0);
    const x=pointCount===1?plotLeft+plotWidth/2:plotLeft+(hasTimeRange?(timestamps[index]-firstTime)/timeSpan:index/(pointCount-1))*plotWidth;
    const y=plotBottom-Math.min(1,value/axisMaximum)*plotHeight;
    return {...point,x,y};
  });
  const ticks=Array.from({length:5},(_,index)=>axisMaximum*(4-index)/4);
  const formatY=value=>percentageMetric
    ?new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{maximumFractionDigits:0}).format(value)+'%'
    :metric==='network'?fmtBytes(value)+'/s'
    :new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{maximumFractionDigits:2}).format(value);
  const grid=ticks.map(value=>{
    const y=plotBottom-(value/axisMaximum)*plotHeight;
    return '<line class="chart-grid" x1="'+plotLeft+'" y1="'+y.toFixed(1)+'" x2="'+plotRight+'" y2="'+y.toFixed(1)+'"></line><text class="chart-label" x="'+(plotLeft-7)+'" y="'+(y+3).toFixed(1)+'" text-anchor="end">'+formatY(value)+'</text>';
  }).join('');
  const xTicks=pointCount===1?[{x:points[0].x,timestamp:points[0].timestamp,anchor:'middle',position:'single'}]:[
    {x:plotLeft,timestamp:points[0].timestamp,anchor:'start',position:'first'},
    {x:(plotLeft+plotRight)/2,timestamp:hasTimeRange?(firstTime+timeSpan/2):points[Math.floor(pointCount/2)].timestamp,anchor:'middle',position:'middle'},
    {x:plotRight,timestamp:points[pointCount-1].timestamp,anchor:'end',position:'last'}
  ];
  const xLabels=xTicks.map(tick=>'<line class="chart-grid chart-grid-vertical chart-grid-'+tick.position+'" x1="'+tick.x.toFixed(1)+'" y1="'+plotTop+'" x2="'+tick.x.toFixed(1)+'" y2="'+plotBottom+'"></line><text class="chart-label chart-label-x chart-label-'+tick.position+'" x="'+tick.x.toFixed(1)+'" y="125" text-anchor="'+tick.anchor+'">'+chartTimeLabel(Number(tick.timestamp),hasTimeRange?timeSpan:0,crossesYear)+'</text>').join('');
  const segments=[];
  points.forEach(point=>{
    const current=segments[segments.length-1];
    if(!current||Number(point.timestamp)-Number(current[current.length-1].timestamp)>CHART_GAP_SECONDS)segments.push([point]);
    else current.push(point);
  });
  const gapMarkers=[];
  for(let index=1;index<segments.length;index++){
    const previous=segments[index-1][segments[index-1].length-1],next=segments[index][0];
    gapMarkers.push('<line class="chart-gap-mark" x1="'+((previous.x+next.x)/2).toFixed(1)+'" y1="'+plotTop+'" x2="'+((previous.x+next.x)/2).toFixed(1)+'" y2="'+plotBottom+'"></line>');
  }
  const drawing=segments.map(segment=>{
    if(segment.length===1)return '<circle class="history-point" cx="'+segment[0].x.toFixed(1)+'" cy="'+segment[0].y.toFixed(1)+'" r="3"></circle>';
    const coords=segment.map(point=>point.x.toFixed(1)+','+point.y.toFixed(1)).join(' ');
    const first=segment[0],last=segment[segment.length-1];
    return '<polygon class="area" points="'+first.x.toFixed(1)+','+first.y.toFixed(1)+' '+coords+' '+last.x.toFixed(1)+','+plotBottom+' '+first.x.toFixed(1)+','+plotBottom+'"></polygon><polyline class="line" points="'+coords+'"></polyline>';
  }).join('');
  const axes='<line class="chart-axis" x1="'+plotLeft+'" y1="'+plotTop+'" x2="'+plotLeft+'" y2="'+plotBottom+'"></line><line class="chart-axis" x1="'+plotLeft+'" y1="'+plotBottom+'" x2="'+plotRight+'" y2="'+plotBottom+'"></line>';
  const id='chart-'+(++state.chartSequence);state.chartData[id]={metric,points};
  const caption='<text class="chart-axis-caption" x="'+((plotLeft+plotRight)/2)+'" y="143" text-anchor="middle">'+tr('本地时间')+'</text>';
  return '<svg class="mini-chart" data-chart-id="'+id+'" viewBox="0 0 '+width+' '+height+'" preserveAspectRatio="none" role="img" tabindex="0" aria-label="'+esc(tr('历史图表：横轴为本地时间，纵轴为指标数值。可用左右方向键查看采样点。'))+'"><rect class="chart-hit" x="0" y="0" width="'+width+'" height="'+height+'" fill="transparent" pointer-events="all"></rect>'+grid+xLabels+gapMarkers.join('')+axes+drawing+caption+'<line class="chart-crosshair" x1="-10" y1="'+plotTop+'" x2="-10" y2="'+plotBottom+'"></line><circle class="chart-hover" cx="-10" cy="-10" r="4"></circle></svg>';
}
function bindChartTooltip(chart){
  const tooltip=document.getElementById('chart-tooltip');const data=state.chartData[chart.dataset.chartId];
  if(!tooltip||!data||!data.points.length)return;
  let hideTimer=null;
  const hide=()=>{
    clearTimeout(hideTimer);tooltip.classList.remove('visible');
    const marker=chart.querySelector('.chart-hover'),crosshair=chart.querySelector('.chart-crosshair');
    if(marker){marker.setAttribute('cx','-10');marker.setAttribute('cy','-10')}
    if(crosshair){crosshair.setAttribute('x1','-10');crosshair.setAttribute('x2','-10')}
  };
  const showPoint=(point,index,clientX,clientY)=>{
    const rect=chart.getBoundingClientRect();if(!rect.width)return;
    chart.dataset.activeIndex=String(index);
    const date=new Date(point.timestamp*1000);const dateText=Number.isFinite(date.getTime())?date.toLocaleString(LANGUAGE_LOCALE[state.language]||'en-US'):'—';
    let valueText;
    if(data.metric==='network')valueText=point.rx==null?fmtBytes(point.value)+'/s':fmtBytes(point.value)+'/s  (↓ '+fmtBytes(point.rx||0)+'/s · ↑ '+fmtBytes(point.tx||0)+'/s)';
    else if(data.metric==='load')valueText=Number(point.value).toFixed(2);
    else valueText=Number(point.value).toFixed(1)+'%';
    tooltip.textContent=dateText+'\n'+tr((metrics[data.metric]||['Metric'])[0])+': '+valueText;tooltip.classList.add('visible');
    const bounds=tooltip.getBoundingClientRect();let left=clientX+14,top=clientY+14;
    if(left+bounds.width>window.innerWidth-8)left=clientX-bounds.width-14;
    if(top+bounds.height>window.innerHeight-8)top=clientY-bounds.height-14;
    tooltip.style.left=Math.max(8,left)+'px';tooltip.style.top=Math.max(8,top)+'px';
    const marker=chart.querySelector('.chart-hover'),crosshair=chart.querySelector('.chart-crosshair');
    if(marker){marker.setAttribute('cx',point.x);marker.setAttribute('cy',point.y)}
    if(crosshair){crosshair.setAttribute('x1',point.x);crosshair.setAttribute('x2',point.x)}
  };
  const showPointer=event=>{
    const rect=chart.getBoundingClientRect();if(!rect.width)return;
    const chartX=Math.max(0,Math.min(320,(event.clientX-rect.left)/rect.width*320));
    let index=0;
    for(let candidate=1;candidate<data.points.length;candidate++){
      if(Math.abs(data.points[candidate].x-chartX)<Math.abs(data.points[index].x-chartX))index=candidate;
    }
    showPoint(data.points[index],index,event.clientX,event.clientY);
    if(event.pointerType==='touch'){clearTimeout(hideTimer);hideTimer=setTimeout(hide,2500)}
  };
  const showActive=()=>{
    const index=Math.max(0,Math.min(data.points.length-1,Number(chart.dataset.activeIndex)||0));
    const point=data.points[index],rect=chart.getBoundingClientRect();
    showPoint(point,index,rect.left+point.x/320*rect.width,rect.top+point.y/148*rect.height);
  };
  chart.addEventListener('pointerdown',showPointer);
  chart.addEventListener('pointermove',showPointer);
  chart.addEventListener('pointerleave',event=>{if(event.pointerType!=='touch')hide()});
  chart.addEventListener('pointercancel',hide);
  chart.addEventListener('focus',showActive);
  chart.addEventListener('keydown',event=>{
    let index=Math.max(0,Math.min(data.points.length-1,Number(chart.dataset.activeIndex)||0));
    if(event.key==='ArrowLeft')index=Math.max(0,index-1);
    else if(event.key==='ArrowRight')index=Math.min(data.points.length-1,index+1);
    else if(event.key==='Home')index=0;
    else if(event.key==='End')index=data.points.length-1;
    else return;
    event.preventDefault();chart.dataset.activeIndex=String(index);showActive();
  });
  chart.addEventListener('blur',hide);
}
function bindWidget(el,w){
  el.querySelectorAll('.mini-chart[data-chart-id]').forEach(chart=>bindChartTooltip(chart));
  if(!w.transient){el.ondragstart=()=>{state.dragged=el;el.classList.add('dragging')};el.ondragend=()=>{state.dragged=null;el.classList.remove('dragging');document.querySelectorAll('.drag-over').forEach(x=>x.classList.remove('drag-over'))}}
  const remove=el.querySelector('.remove-widget');if(remove)remove.onclick=()=>{state.config.widgets=state.config.widgets.filter(x=>x.id!==w.id);draw();saveConfig().catch(error=>toast(error.message))};
  const iface=el.querySelector('.iface-select');if(iface)iface.onchange=()=>{state.history[w.node+':iface']=iface.value;draw()};
  const range=el.querySelector('.history-select');if(range)range.onchange=()=>{const selection=historySelectionKey(w.node,w.metric,range.dataset.interface||'');if(range.value==='custom'){draw();showHistoryRange(w.node,w.metric,range.dataset.interface||'');return}delete state.historyCustom[selection];state.historyRanges[selection]=range.value;draw()};
  const custom=el.querySelector('.history-custom');if(custom)custom.onclick=()=>showHistoryRange(w.node,w.metric,custom.dataset.interface||'');
  const disk=el.querySelector('[data-disk]');if(disk)disk.onclick=()=>showDisks(w.node)
}
async function saveConfig(){await api('/api/config','POST',{assets:state.config.assets,widgets:state.config.widgets,theme:state.config.theme,history_retention_days:state.config.history_retention_days});state.config=await api('/api/config')}
function modal(content,wide){const box=document.getElementById('modal');box.className='modal-backdrop open';box.innerHTML='<section class="modal '+(wide?'wide-modal':'')+'">'+content+'</section>';localizeDOM(box);box.onclick=e=>{if(e.target===box)closeModal()};const close=box.querySelectorAll('[data-close]');close.forEach(x=>x.onclick=closeModal);state.modal=box}
function closeModal(){const box=document.getElementById('modal');if(box){box.className='modal-backdrop';box.innerHTML=''}state.modal=null}
function showDisks(id){const node=nodeFor(id);if(!node||!node.metrics)return;const rows=node.metrics.disk.partitions||[];modal('<header class="modal-head"><h3>磁盘与分区 · '+esc(node.name)+'</h3><button class="close" data-close>×</button></header><div style="overflow:auto"><table class="data-table"><thead><tr><th>挂载点</th><th>设备</th><th>文件系统</th><th>已用 / 总量</th><th>使用率</th></tr></thead><tbody>'+rows.map(x=>'<tr><td>'+esc(x.mount)+'</td><td>'+esc(x.device)+'</td><td>'+esc(x.filesystem)+'</td><td>'+fmtBytes(x.used)+' / '+fmtBytes(x.total)+'</td><td>'+x.percent+'%</td></tr>').join('')+'</tbody></table></div>',true)}
function showAddWidget(){const assets=[{id:'local',name:nodeFor('local')?.name||'本机'}].concat(state.config.assets||[]);modal('<header class="modal-head"><h3>添加监控卡片</h3><button class="close" data-close>×</button></header><form id="widget-form"><div class="form-grid"><div class="field full"><label>网络资产</label><select id="widget-node">'+assets.map(a=>'<option value="'+esc(a.id)+'">'+esc(a.name)+'</option>').join('')+'</select></div><div class="field full"><label>监控项目</label><select id="widget-metric">'+Object.entries(metrics).filter(([key])=>key!=='info').map(([k,v])=>'<option value="'+k+'">'+v[0]+'</option>').join('')+'</select></div></div><div class="error-message" id="widget-error"></div><div class="modal-actions"><button type="button" class="button subtle" data-close>取消</button><button class="button primary">添加卡片</button></div></form>');document.getElementById('widget-form').onsubmit=async e=>{e.preventDefault();if(state.config.widgets.length>=32){document.getElementById('widget-error').textContent=tr('最多添加 32 张卡片');return}const node=document.getElementById('widget-node').value,metric=document.getElementById('widget-metric').value;state.config.widgets.push({id:crypto.randomUUID?crypto.randomUUID():('w-'+Date.now()),node:node,metric:metric});closeModal();draw();try{await saveConfig()}catch(err){toast(err.message)}}}
function showHistorySettings(){showSettings()}
function showSettings(){
  const current=Number(state.config.history_retention_days)||7;
  const retention=[1,3,7,14,30].map(value=>'<option value="'+value+'" '+(value===current?'selected':'')+'>'+tr(value+' 天')+'</option>').join('');
  const themes=[['dark','深色'],['light','浅色']].map(([value,label])=>'<option value="'+value+'" '+(state.config.theme===value?'selected':'')+'>'+tr(label)+'</option>').join('');
  const languages=Object.entries(LANGUAGE_NAMES).map(([code,name])=>'<option value="'+code+'" '+(state.language===code?'selected':'')+'>'+name+'</option>').join('');
  modal('<header class="modal-head"><div><h3>设置</h3><div class="helper">配置语言、外观和历史数据保留期限。</div></div><button class="close" data-close aria-label="Close">×</button></header><form id="settings-form"><div class="form-grid"><div class="field"><label for="settings-language">Language</label><select id="settings-language">'+languages+'</select></div><div class="field"><label for="settings-theme">主题</label><select id="settings-theme">'+themes+'</select></div><div class="field full"><label for="retention-days">数据保留期限 · 保留时间</label><select id="retention-days">'+retention+'</select></div></div><div class="helper">历史样本每分钟保存到本地 JSON 数据库。</div><div class="helper">缩短保留期限会立即删除超出期限的旧数据。</div><div class="error-message" id="settings-error"></div><div class="modal-actions"><button type="button" class="button subtle" data-close>取消</button><button type="submit" class="button primary">保存设置</button></div></form>');
  document.getElementById('settings-form').onsubmit=async event=>{
    event.preventDefault();const nextLanguage=document.getElementById('settings-language').value;
    const nextTheme=document.getElementById('settings-theme').value;const nextDays=Number(document.getElementById('retention-days').value);
    try{
      await api('/api/config','POST',{assets:state.config.assets,widgets:state.config.widgets,theme:nextTheme,history_retention_days:nextDays});
      state.config=await api('/api/config');state.historical={};
      if(nextDays<current){for(const selection of Object.keys(state.historyCustom)){const custom=state.historyCustom[selection];if(custom.start<Date.now()/1000-nextDays*24*60*60){delete state.historyCustom[selection];delete state.historyRanges[selection]}}}
      state.language=LANGUAGE_NAMES[nextLanguage]?nextLanguage:'en';
      try{localStorage.setItem('tinywatch.language',state.language)}catch(error){}
      document.documentElement.lang=state.language;setTheme(state.config.theme);closeModal();render();toast('设置已保存');
    }catch(error){const target=document.getElementById('settings-error');if(target)target.textContent=tr(error.message)}
  };
}
function showAssets(){
  const assets=state.config.assets||[];
  const rows=assets.map(asset=>'<div class="disk-line"><span><strong>'+esc(asset.name)+'</strong> '+
    (asset.secure_transport?'':'<span class="tag bad">'+tr('HTTPS required')+'</span>')+
    '<div class="metric-sub">'+esc(asset.url)+'</div></span><button class="button danger" data-remove="'+esc(asset.id)+'">移除</button></div>').join('');
  modal('<header class="modal-head"><div><h3>网络资产</h3><div class="helper">配置远程 TinyWatch 节点。每个节点需在“代理令牌”处填入目标主机生成的令牌。</div></div><button class="close" data-close>×</button></header><div>'+rows+'</div><form id="asset-form" style="margin-top:16px"><div class="form-grid"><div class="field"><label>资产名称</label><input id="asset-name" required maxlength="80" placeholder="例如：edge-node-01"></div><div class="field"><label>服务地址</label><input id="asset-url" required placeholder="https://node.example:8765"></div><div class="field full"><label>代理令牌</label><input id="asset-password" required autocomplete="off" placeholder="在目标节点设置页复制代理令牌"></div></div><div class="helper">'+tr('远程节点必须使用有效的 HTTPS 证书；HTTP 仅适用于本机 localhost 或回环地址。')+'</div><div class="error-message" id="asset-error"></div><div class="modal-actions"><button class="button primary">添加资产</button></div></form><div class="helper">本机代理令牌（复制到其他节点的资产配置中）：<br><code style="overflow-wrap:anywhere">'+esc(state.config.agent_token)+'</code></div>');
  document.getElementById('asset-form').onsubmit=async event=>{
    event.preventDefault();
    const asset={id:'a-'+(crypto.randomUUID?crypto.randomUUID():Date.now()),name:document.getElementById('asset-name').value,url:document.getElementById('asset-url').value,password:document.getElementById('asset-password').value};
    const list=state.config.assets.slice();list.push(asset);
    try{await api('/api/config','POST',{assets:list,widgets:state.config.widgets,theme:state.config.theme});state.config=await api('/api/config');closeModal();draw();await refresh();toast('网络资产已添加')}
    catch(error){document.getElementById('asset-error').textContent=tr(error.message)}
  };
  document.querySelectorAll('[data-remove]').forEach(button=>button.onclick=async()=>{
    const list=state.config.assets.filter(asset=>asset.id!==button.dataset.remove);
    state.config.assets=list;state.config.widgets=state.config.widgets.filter(widget=>widget.node==='local'||list.some(asset=>asset.id===widget.node));
    try{await saveConfig();showAssets();draw();toast('资产已移除')}catch(error){toast(error.message)}
  });
}
boot();
</script></body></html>'''


def _session_from_request(handler):
    cookie_header = handler.headers.get("Cookie", "")
    try:
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get("tw_session")
        token = morsel.value if morsel else ""
    except (CookieError, ValueError):
        token = ""
    if not token:
        return False
    now = time.time()
    with STATE_LOCK:
        expiry = SESSIONS.get(token, 0)
        if expiry <= now:
            SESSIONS.pop(token, None)
            return False
        SESSIONS[token] = now + 12 * 60 * 60
    return True


def _agent_authorized(handler):
    supplied = handler.headers.get("X-TinyWatch-Token", "")
    if not supplied:
        authorization = handler.headers.get("Authorization", "")
        if authorization.startswith("Bearer "):
            supplied = authorization[7:]
    expected = STORE.data.get("agent_token", "")
    return bool(expected and supplied and secrets.compare_digest(str(supplied), str(expected)))


class TinyWatchHandler(BaseHTTPRequestHandler):
    server_version = "TinyWatch/" + APP_VERSION
    sys_version = ""

    def log_message(self, fmt, *args):
        # Keep the compact access log useful without ever echoing request bodies.
        sys.stdout.write("[%s] %s %s\n" % (self.log_date_time_string(), self.address_string(), fmt % args))

    def _send(self, status, body, content_type="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            encoded = body.encode("utf-8")
        else:
            encoded = body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
        if headers:
            for name, value in headers.items():
                self.send_header(name, value)
        self.end_headers()
        try:
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status, value, headers=None):
        self._send(status, json.dumps(value, ensure_ascii=False, separators=(",", ":")), headers=headers)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("请求长度无效")
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("请求内容过大")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("请求内容必须是 JSON 对象")
        return value

    def _require_session(self):
        if not _session_from_request(self):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "请先登录"})
            return False
        return True

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/" or path == "/index.html":
            self._send(HTTPStatus.OK, HTML_PAGE, "text/html; charset=utf-8")
            return
        if path == "/api/status":
            self._json(HTTPStatus.OK, {"setup_required": STORE.data.get("password") is None,
                                      "authenticated": _session_from_request(self)})
            return
        if path == "/api/agent/metrics":
            if not _agent_authorized(self):
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "代理令牌无效"})
                return
            try:
                self._json(HTTPStatus.OK, collect_snapshot())
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": _safe_text(exc, 180)})
            return
        if path == "/api/config":
            if not self._require_session():
                return
            self._json(HTTPStatus.OK, _config_for_browser())
            return
        if path == "/api/metrics":
            if not self._require_session():
                return
            try:
                self._json(HTTPStatus.OK, collect_cluster_snapshot())
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": _safe_text(exc, 180)})
            return
        if path == "/api/history":
            if not self._require_session():
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            node_id = query.get("node", ["local"])[0]
            metric = query.get("metric", [""])[0]
            range_name = query.get("range", ["1h"])[0]
            interface = query.get("iface", [""])[0]
            if len(node_id) > 100 or metric not in ("cpu", "memory", "disk", "network", "load") or (range_name not in HISTORY_RANGES and range_name != "custom"):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "历史数据查询参数无效"})
                return
            try:
                start = end = None
                if range_name == "custom":
                    start = float(query.get("start", [""])[0])
                    end = float(query.get("end", [""])[0])
                self._json(HTTPStatus.OK, _history_response(node_id, metric, range_name, interface[:120], start, end))
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_text(exc, 180)})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "未找到"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        try:
            value = self._read_json()
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_text(exc, 180)})
            return

        if path == "/api/setup":
            with STORE.lock:
                if STORE.data.get("password") is not None:
                    self._json(HTTPStatus.CONFLICT, {"error": "管理员密码已设置"})
                    return
                if not self.client_address or self.client_address[0] not in ("127.0.0.1", "::1"):
                    self._json(HTTPStatus.FORBIDDEN, {"error": "首次设置必须在运行 TinyWatch 的主机上通过 localhost 完成"})
                    return
                password = value.get("password")
                if not isinstance(password, str) or len(password) < 10:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "密码至少需要 10 个字符"})
                    return
                if len(password) > 1024:
                    self._json(HTTPStatus.BAD_REQUEST, {"error": "密码长度超出限制"})
                    return
                STORE.data["password"] = _password_hash(password)
                STORE.save()
            self._create_session()
            return

        if path == "/api/login":
            address = self.client_address[0] if self.client_address else "unknown"
            now = time.time()
            with STATE_LOCK:
                recent = [stamp for stamp in LOGIN_FAILURES.get(address, []) if now - stamp < 60]
                LOGIN_FAILURES[address] = recent
                if len(recent) >= 8:
                    self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "登录尝试过多，请一分钟后再试"})
                    return
            password = value.get("password")
            record = STORE.data.get("password")
            if not record:
                self._json(HTTPStatus.CONFLICT, {"error": "尚未设置管理员密码"})
                return
            if not isinstance(password, str) or len(password) > 1024 or not _password_matches(password, record):
                with STATE_LOCK:
                    LOGIN_FAILURES.setdefault(address, []).append(now)
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "密码不正确"})
                return
            with STATE_LOCK:
                LOGIN_FAILURES.pop(address, None)
            self._create_session()
            return

        if not self._require_session():
            return
        if path == "/api/logout":
            cookie_header = self.headers.get("Cookie", "")
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_header)
                morsel = cookie.get("tw_session")
                if morsel:
                    with STATE_LOCK:
                        SESSIONS.pop(morsel.value, None)
            except (ValueError, Exception):
                pass
            self._json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": "tw_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
            return
        if path == "/api/config":
            try:
                self._save_config(value)
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._json(HTTPStatus.OK, {"ok": True})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "未找到"})

    def _create_session(self):
        token = secrets.token_urlsafe(32)
        with STATE_LOCK:
            SESSIONS[token] = time.time() + 12 * 60 * 60
        self._json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": "tw_session=" + token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=43200"})

    def _save_config(self, value):
        raw_assets = value.get("assets", [])
        raw_widgets = value.get("widgets", [])
        if not isinstance(raw_assets, list) or len(raw_assets) > MAX_ASSETS:
            raise ValueError("最多配置 %d 个远程资产" % MAX_ASSETS)
        if not isinstance(raw_widgets, list) or len(raw_widgets) > MAX_WIDGETS:
            raise ValueError("监控卡片最多 %d 张" % MAX_WIDGETS)
        retention_days = value.get("history_retention_days", _history_retention_days())
        if isinstance(retention_days, bool) or retention_days not in HISTORY_RETENTION_OPTIONS:
            raise ValueError("历史数据保留天数无效")
        with STORE.lock:
            previous_retention_days = STORE.persisted_retention_days
            previous = {item["id"]: item for item in STORE.data.get("assets", [])}
            assets = []
            identifiers = set()
            for item in raw_assets:
                if not isinstance(item, dict):
                    raise ValueError("资产配置格式无效")
                asset_id = str(item.get("id", ""))
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", asset_id) or asset_id == "local":
                    raise ValueError("资产标识格式无效")
                if asset_id in identifiers:
                    raise ValueError("资产标识不能重复")
                identifiers.add(asset_id)
                name = _safe_text(item.get("name", "").strip() if isinstance(item.get("name"), str) else "", 80).strip()
                if not name:
                    raise ValueError("资产名称不能为空")
                url = _validate_asset_url(item.get("url", ""))
                parsed_url = urllib.parse.urlsplit(url)
                old_asset = previous.get(asset_id, {})
                if (parsed_url.scheme == "http" and not _is_loopback_host(parsed_url.hostname)
                        and (not old_asset or old_asset.get("url") != url)):
                    raise ValueError("远程资产必须使用 HTTPS；HTTP 仅限 localhost / 回环地址")
                password = item.get("password")
                if not isinstance(password, str) or not password:
                    password = previous.get(asset_id, {}).get("password", "")
                if not password or len(password) > 512:
                    raise ValueError("资产代理令牌不能为空且不能超过 512 个字符")
                assets.append({"id": asset_id, "name": name, "url": url, "password": password})
            valid_nodes = {"local"} | identifiers
            metrics = {"cpu", "memory", "network", "disk", "load", "processes", "logins", "dns", "info"}
            widgets = []
            widget_ids = set()
            for item in raw_widgets:
                if not isinstance(item, dict):
                    raise ValueError("卡片配置格式无效")
                widget_id = str(item.get("id", ""))
                node_id = str(item.get("node", ""))
                metric = str(item.get("metric", ""))
                if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", widget_id) or widget_id in widget_ids:
                    raise ValueError("卡片标识格式无效或重复")
                if node_id not in valid_nodes or metric not in metrics:
                    raise ValueError("卡片的资产或监控项目无效")
                widget_ids.add(widget_id)
                widgets.append({"id": widget_id, "node": node_id, "metric": metric})
            theme = value.get("theme", STORE.data.get("theme", "dark"))
            if theme not in ("dark", "light"):
                theme = "dark"
            STORE.data["assets"] = assets
            STORE.data["widgets"] = widgets
            STORE.data["theme"] = theme
            STORE.data["history_retention_days"] = retention_days
            retention_cutoff = time.time() - retention_days * 24 * 60 * 60
            pruned = _prune_history_database(STORE.data, retention_cutoff)
            backup_retention_days = retention_days if pruned or previous_retention_days != retention_days else None
            STORE.save(backup_retention_days=backup_retention_days)


class TinyWatchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main(argv=None):
    parser = argparse.ArgumentParser(description="TinyWatch - dependency-free server monitoring dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="listen address; use 0.0.0.0 for LAN access")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="HTTP listening port (default: %(default)s)")
    parser.add_argument("--data", default=str(default_store_path()), help="JSON database path (default: ~/.tinywatch/data.json)")
    parser.add_argument("--version", action="version", version=APP_NAME + " " + APP_VERSION)
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    global STORE
    try:
        STORE = JsonStore(args.data)
        server = TinyWatchServer((args.host, args.port), TinyWatchHandler)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if STORE.recovered_from_backup:
        print("Warning: TinyWatch restored its JSON database from the known-good .bak file.", file=sys.stderr)
        print("Review the restored settings and preserve the .corrupt-* file for inspection.", file=sys.stderr)
    actual_port = server.server_address[1]
    display_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print("%s %s listening on http://%s:%d" % (APP_NAME, APP_VERSION, display_host, actual_port))
    print("JSON database: %s" % STORE.path)
    if args.host in ("0.0.0.0", "::"):
        print("LAN mode enabled; protect access with a firewall and use HTTPS via a trusted reverse proxy.")
    history_stop = threading.Event()
    history_thread = threading.Thread(target=_history_sampler, args=(history_stop,),
                                      name="tinywatch-history", daemon=True)
    history_thread.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping TinyWatch…")
    finally:
        history_stop.set()
        history_thread.join(timeout=45)
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

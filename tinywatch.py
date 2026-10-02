#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TinyWatch server, system collectors and embedded browser UI.

Run ``python3 tinywatch.py`` and open http://127.0.0.1:8765.
"""

from __future__ import annotations

import argparse
import bisect
import base64
import copy
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
import ssl
import tempfile
import zipfile
from collections import OrderedDict, deque
from contextlib import contextmanager
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

APP_NAME = "TinyWatch"
APP_VERSION = "1.0.0"
DEFAULT_PORT = 8765
PASSWORD_ITERATIONS = 310_000
MAX_BODY_BYTES = 1_000_000
MAX_ASSETS = 16
MAX_WIDGETS = 32
HISTORY_INTERVAL = 60
HISTORY_GAP_SECONDS = 90
HISTORY_COMPACT_INTERVAL = 3600
MAX_ALERT_RULES = 32
MAX_INCIDENTS = 1024
ALERT_METRICS = ("cpu", "memory", "disk", "network", "load", "offline", "stale")
CLUSTER_CACHE_SECONDS = 5
HISTORY_RETENTION_DEFAULT_DAYS = 7
HISTORY_RETENTION_OPTIONS = (1, 3, 7, 14, 30)
HISTORY_RETENTION_MAX = 30 * 24 * 60 * 60
HISTORY_RANGES = {"1h": 60 * 60, "6h": 6 * 60 * 60, "24h": 24 * 60 * 60, "3d": 3 * 24 * 60 * 60, "7d": 7 * 24 * 60 * 60, "14d": 14 * 24 * 60 * 60, "30d": 30 * 24 * 60 * 60}
HISTORY_LAST_WRITE = 0.0
# Expensive native commands are cached independently of fast resource counters.
COLLECTOR_INTERVALS = {"cpu": 2, "memory": 2, "network": 2, "load": 2,
                       "disk": 30, "processes": 10, "logins": 60, "dns": 60, "info": 30}
COLLECTOR_CACHE = {}
COLLECTOR_CACHE_LOCK = threading.RLock()
SLOW_COLLECTORS = {"disk", "processes", "logins", "dns", "info"}
DETAILS_RUNNING = False
MAX_SERVICES = 24
MAX_NOTIFICATION_JOBS = 128
MAX_TIMELINE_EVENTS = 2048
SAMPLE_LOCK = threading.RLock()
SNAPSHOT_LOCK = threading.Lock()
SNAPSHOT_CACHE = {"sampled_at": 0.0, "data": None}
STATE_LOCK = threading.RLock()
SESSIONS = {}
LOGIN_FAILURES = {}
AUTH_STATE_LAST_CLEANUP = 0.0
AUTH_STATE_CLEANUP_INTERVAL = 60
MAX_ACTIVE_SESSIONS = 4096
MAX_LOGIN_FAILURE_ADDRESSES = 4096
SETUP_TOKEN = None
SECURE_COOKIE = False
CLUSTER_SNAPSHOT_LOCK = threading.Lock()
CLUSTER_REFRESH_LOCK = threading.Lock()
CLUSTER_SNAPSHOT_CACHE = {"sampled_at": 0.0, "data": None, "generation": 0}
REMOTE_STATUS_LOCK = threading.Lock()
REMOTE_LAST_SUCCESS = {}
ASSET_CACHE = {}
ASSET_CACHE_LOCK = threading.RLock()
ASSET_ACTIVITY = {"last_poll": 0.0, "wake": False}
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
            "percent": round(100.0 * used / total, 1) if total else 0.0,
            "supported": bool(total)}


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
            if hasattr(os, "statvfs"):
                try:
                    inode = os.statvfs(mount)
                    if inode.f_files:
                        result[-1].update(inode_total=inode.f_files, inode_free=inode.f_ffree,
                                          inode_percent=round(100*(inode.f_files-inode.f_ffree)/inode.f_files, 1))
                except OSError:
                    pass
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
            "percent": round(100.0 * used / total, 1) if total else 0.0,
            "supported": bool(total)}


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
    return {"interfaces": interfaces, "supported": bool(current),
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
                start_ticks = _number(fields[19])
                if old and (len(old) < 3 or old[2] != start_ticks):
                    old = None
                elapsed = max(0.01, now - old[1]) if old else 0
                cpu_pct = max(0.0, min(100.0 * (os.cpu_count() or 1),
                                       100.0 * (cpu_seconds - old[0]) / elapsed)) if old and elapsed else 0.0
                new_previous[pid] = (cpu_seconds, now, start_ticks)
                process_network = network_rates.get(pid) if network_rates is not None else None
                rows.append({"pid": pid, "started": start_ticks, "name": _safe_text(command, 100), "user": str(uid) if uid is not None else "—",
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
        # Keep the hosts-file fallback distinguishable from a resolver cache.
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


def _partition_id(item):
    """Stable partition identity; labels stay separate from API/storage keys."""
    identity = str(item.get("device", "")) + "\0" + str(item.get("mount", ""))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]


def _collect_safely(name, collector, fallback, errors, refresh=False):
    """Cache collector results and isolate platform errors."""
    now = time.monotonic()
    with COLLECTOR_CACHE_LOCK:
        cached = COLLECTOR_CACHE.get(name)
    interval = COLLECTOR_INTERVALS.get(name, 30)
    if DETAILS_RUNNING and name in SLOW_COLLECTORS and not refresh:
        if not cached:
            errors[name] = "Waiting for background collection"
            return copy.deepcopy(fallback)
        if cached["error"]:
            errors[name] = cached["error"]
        elif time.time() - cached["stamp"] > max(120, interval * 3):
            errors[name] = "Background collection is stale"
        return copy.deepcopy(cached["data"])
    if cached and now - cached["at"] < (min(interval, 10) if cached["error"] else interval):
        if cached["error"]:
            errors[name] = cached["error"]
        return copy.deepcopy(cached["data"])
    error = None
    try:
        data = collector()
        if name == "disk":
            for item in data.get("partitions", []):
                item["id"] = _partition_id(item)
    except Exception as exc:
        error = _safe_text(exc, 180) or "collector failed"
        errors[name] = error
        data = fallback
    with COLLECTOR_CACHE_LOCK:
        COLLECTOR_CACHE[name] = {"at": time.monotonic(), "stamp": time.time(),
                                                              "duration_ms": round((time.monotonic() - now) * 1000, 1),
                                 "data": copy.deepcopy(data), "error": error}
    return data


def _collect_snapshot_now():
    """Collect current host metrics and report independent collector failures."""
    with SAMPLE_LOCK:
        errors = {}
        logical_cores = os.cpu_count() or 1
        cpu = _collect_safely("cpu", _cpu_snapshot,
                              {"percent": 0.0, "available": False, "cores": [],
                               "logical_cores": logical_cores}, errors)
        memory = _collect_safely("memory", _memory_snapshot,
                                 {"total": 0, "used": 0, "available": 0, "percent": 0.0,
                                  "supported": False}, errors)
        disks = _collect_safely("disk", _disk_snapshot,
                                {"partitions": [], "total": 0, "used": 0, "percent": 0.0,
                                 "supported": False}, errors)
        network = _collect_safely("network", _network_snapshot,
                                  {"interfaces": [], "rx_rate": 0.0, "tx_rate": 0.0,
                                   "supported": False}, errors)
        load = _collect_safely("load", _load_snapshot, [], errors)
        if platform.system().lower() == "windows" and not load and cpu.get("available"):
            load = [round(cpu["percent"] / 100.0, 2)]
        system = platform.system().lower()
        process_collector = (_processes_linux if system == "linux" else
                             _processes_windows if system == "windows" else _processes_other)
        processes = _collect_safely("processes", process_collector, [], errors)
        logins = _collect_safely("logins", _login_events, [], errors)
        dns = _collect_safely("dns", _dns_cache,
                              {"source": "unavailable", "count": 0, "entries": []}, errors)

        info = _collect_safely("info", _host_profile,
                               {"hostname": "unknown", "cpu": "unavailable",
                                "logical_cores": logical_cores, "memory_total": memory["total"],
                                "system": "unavailable", "os": system or "unknown",
                                "release": "unavailable", "version": "unavailable",
                                "architecture": "unavailable", "uptime_seconds": 0,
                                "uptime": "unavailable", "sessions": [],
                                "python": platform.python_version()}, errors)
        if memory.get("supported", True) and memory.get("total"):
            info["memory_total"] = memory["total"]
        return {"sampled_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "cpu": cpu, "memory": memory, "disk": disks, "network": network, "load": load,
                "processes": processes, "logins": logins, "dns": dns, "info": info,
                "collector_errors": errors,
                "collector_status": _collector_metadata()}


def _collector_metadata():
    with COLLECTOR_CACHE_LOCK:
        return {name: {"sampled_at": entry["stamp"], "interval_seconds": COLLECTOR_INTERVALS[name],
                       "duration_ms": entry["duration_ms"]} for name, entry in COLLECTOR_CACHE.items()}


def _host_profile():
    uname = platform.uname()
    uptime = _uptime_seconds()
    with COLLECTOR_CACHE_LOCK:
        memory = COLLECTOR_CACHE.get("memory", {}).get("data", {})
    return {"hostname": _safe_text(socket.gethostname(), 160), "cpu": _cpu_brand(),
            "logical_cores": os.cpu_count() or 1, "memory_total": memory.get("total", 0),
            "system": _safe_text(platform.platform(), 240), "os": _safe_text(uname.system, 80),
            "release": _safe_text(uname.release, 120), "version": _safe_text(uname.version, 220),
            "architecture": _safe_text(uname.machine, 80), "uptime_seconds": uptime,
            "uptime": _format_uptime(uptime), "sessions": _sessions(), "python": platform.python_version()}


def _details_sampler(stop_event):
    """Refresh slow collectors outside the resource sample lock."""
    system = platform.system().lower()
    process_collector = _processes_linux if system == "linux" else _processes_windows if system == "windows" else _processes_other
    collectors = {"info": _host_profile, "disk": _disk_snapshot, "processes": process_collector,
                  "logins": _login_events, "dns": _dns_cache}
    while not stop_event.is_set():
        _worker_tick("details")
        for name, collector in collectors.items():
            if stop_event.is_set():
                return
            _collect_safely(name, collector, {} if name in ("info", "disk", "dns") else [], {}, refresh=True)
        stop_event.wait(1)


def default_store_path():
    override = os.environ.get("TINYWATCH_DATA")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".tinywatch" / "data.json"


def empty_database():
    return {"schema": 2, "password": None, "agent_token": secrets.token_urlsafe(32),
            "alert_rules": default_alert_rules(), "alert_states": {}, "incidents": [],
            "timeline": [], "node_fingerprints": {},
            "flight_enabled": False, "job_runs": {}, "flight_records": [], "heartbeats": [], "service_revision": 0, "services": [], "service_states": {}, "service_history": {}, "maintenance": [],
            "notifications": {"enabled": False, "url": ""}, "notification_queue": [],
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


def _mark_changed_rows(database, rows, service=False):
    if STORE is not None and database is STORE.data:
        for row in rows:
            STORE.mark_history_dirty(row["bucket"] if service else row[0])


def _mark_replaced_rows(database, before, after):
    if STORE is None or database is not STORE.data:
        return
    old, new = {}, {}
    for row in before:
        old.setdefault(int(row[0])//86400, []).append(row)
    for row in after:
        new.setdefault(int(row[0])//86400, []).append(row)
    for day in old.keys() | new.keys():
        if old.get(day) != new.get(day):
            STORE.mark_history_dirty(day*86400)


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
                    _mark_changed_rows(database, [point for point in points if isinstance(point, list) and point and _number(point[0]) < cutoff])
                    changed = True
                if not filtered and metric.startswith("disk@"):
                    del node_series[metric]
                else:
                    node_series[metric] = filtered
    incidents = database.get("incidents", [])
    if isinstance(incidents, list):
        retained = [item for item in incidents if isinstance(item, dict) and
                    (item.get("status") == "active" or _number(item.get("resolved_at")) >= cutoff)]
        if retained != incidents:
            database["incidents"] = retained
            changed = True
    records = database.get("flight_records", [])
    kept_records = [record for record in records if record.get("triggered_at", 0) >= cutoff]
    for record in kept_records:
        points = [point for point in record.get("points", []) if point["timestamp"] >= cutoff]
        if len(points) != len(record.get("points", [])):
            record["points"] = points
            record["_bytes"] = sum(len(json.dumps(point, ensure_ascii=False).encode("utf-8")) for point in points)
            changed = True
    if records != kept_records:
        database["flight_records"] = kept_records
        changed = True
    valid_jobs = {job["id"] for job in database.get("heartbeats", [])}
    for identity, rows in list(database.get("job_runs", {}).items()):
        retained_runs = [row for row in rows if row.get("status") == "running" or _number(row.get("finished_at")) >= cutoff]
        if identity not in valid_jobs:
            del database["job_runs"][identity]
            changed = True
        elif retained_runs != rows:
            database["job_runs"][identity] = retained_runs
            changed = True
    events = database.get("timeline", [])
    kept = [event for event in events if isinstance(event, dict) and _number(event.get("timestamp")) >= cutoff]
    if kept != events:
        database["timeline"] = kept
        changed = True
    for service_id, buckets in list(database.get("service_history", {}).items()):
        kept = [bucket for bucket in buckets if bucket.get("last_at", 0) >= cutoff][-2048:]
        if kept != buckets:
            kept_ids = {id(bucket) for bucket in kept}
            _mark_changed_rows(database, [bucket for bucket in buckets if id(bucket) not in kept_ids], service=True)
            database["service_history"][service_id] = kept
            changed = True
    windows = database.get("maintenance", [])
    kept = [window for window in windows if window.get("end", 0) >= cutoff]
    if kept != windows:
        database["maintenance"] = kept
        changed = True
    return changed


WORKER_LOCK = threading.Lock()
WORKER_HEALTH = {}


def _worker_tick(name, **fields):
    with WORKER_LOCK:
        WORKER_HEALTH.setdefault(name, {}).update(last_tick=time.time(), last_tick_monotonic=time.monotonic(), **fields)


def _worker_entry(name, target, stop_event):
    failures = []
    while not stop_event.is_set():
        _worker_tick(name, running=True, failed=False, restarting=False)
        try:
            target(stop_event)
            break
        except Exception as exc:
            now = time.monotonic()
            failures = [stamp for stamp in failures if now-stamp < 600]
            failures.append(now)
            exhausted = len(failures) > 3
            delay = min(30, 2 ** len(failures))
            with WORKER_LOCK:
                record = WORKER_HEALTH[name]
                record.update(running=False, failed=True, restarting=not exhausted,
                              restarts=record.get("restarts", 0)+(0 if exhausted else 1),
                              last_failure_at=int(time.time()), last_error=type(exc).__name__, retry_seconds=delay)
            sys.stderr.write("TinyWatch worker failure: " + name + " (" + type(exc).__name__ + ")\n")
            if exhausted or stop_event.wait(delay):
                break
    with WORKER_LOCK:
        WORKER_HEALTH.setdefault(name, {}).update(running=False, restarting=False)


def _runtime_health(now):
    with WORKER_LOCK:
        workers = copy.deepcopy(WORKER_HEALTH)
    for name, worker in workers.items():
        worker["age_seconds"] = max(0, int(time.monotonic()-worker.pop("last_tick_monotonic", time.monotonic())))
        worker["stale"] = worker["age_seconds"] > (180 if name in ("history", "details") else 30)
    with STORE.lock:
        pending = [job for job in STORE.data.get("notification_queue", []) if job.get("status") == "pending"]
        oldest = max((now-job["created_at"] for job in pending), default=0)
        shards = STORE.path.with_name(STORE.path.name + ".history")
        try:
            shard_bytes = sum(path.stat().st_size for path in shards.iterdir() if HISTORY_FILE_PATTERN.fullmatch(path.name))
        except OSError:
            shard_bytes = None
        return {"workers": workers, "last_persisted_at": STORE.last_success_at,
                "write_failures": STORE.write_failures, "notification_pending": len(pending),
                "notification_oldest_seconds": max(0, int(oldest)), "history_bytes": shard_bytes}


HISTORY_FILE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}-[a-f0-9]{64}\.jsonl")


def _hydrate_history(database, path):
    """Validate all referenced shards before accepting a database generation."""
    manifest = database.pop("history_files", None)
    if manifest is None:
        return database
    if not isinstance(manifest, list) or len(manifest) > 370:
        raise ValueError("Invalid history manifest")
    history, services = {}, {}
    directory = path.with_name(path.name + ".history")
    for name in manifest:
        if not isinstance(name, str) or not HISTORY_FILE_PATTERN.fullmatch(name):
            raise ValueError("Invalid history shard name")
        content = (directory / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != name[11:-6]:
            raise ValueError("History shard checksum mismatch")
        for line in content.splitlines():
            row = json.loads(line)
            if not isinstance(row, list) or len(row) != 4 or row[0] not in ("host", "service"):
                raise ValueError("Invalid history record")
            kind, identity, metric, point = row
            if not isinstance(identity, str) or not isinstance(metric, str):
                raise ValueError("Invalid history identity")
            if kind == "host":
                if not isinstance(point, list) or not point or not isinstance(point[0], (int, float)):
                    raise ValueError("Invalid host history point")
                history.setdefault(identity, {}).setdefault(metric, []).append(point)
            else:
                if not isinstance(point, dict) or not isinstance(point.get("bucket"), (int, float)):
                    raise ValueError("Invalid service history bucket")
                services.setdefault(identity, []).append(point)
    database["history"], database["service_history"] = history, services
    return database


def _validate_runtime_records(database):
    """Reject damaged task or recording state before accepting a generation."""
    runs = database.get("job_runs", {})
    records = database.get("flight_records", [])
    if (not isinstance(database.get("flight_enabled", False), bool) or not isinstance(runs, dict)
            or len(runs) > 24 or not isinstance(records, list) or len(records) > 16):
        raise ValueError("Invalid runtime records")
    for identity, rows in runs.items():
        if not isinstance(identity, str) or not isinstance(rows, list) or len(rows) > 50:
            raise ValueError("Invalid task run history")
        seen = set()
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("id"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", row["id"]) or row["id"] in seen
                    or row.get("status") not in ("running", "success", "failed", "timeout")
                    or not isinstance(row.get("message", ""), str) or len(row.get("message", "")) > 240):
                raise ValueError("Invalid task run record")
            seen.add(row["id"])
            if row["status"] == "running" and _finite_value(row.get("started_at")) is None:
                raise ValueError("Running task has no start time")
            if row["status"] != "running" and _finite_value(row.get("finished_at")) is None:
                raise ValueError("Completed task has no finish time")
        if sum(row["status"] == "running" for row in rows) > 4:
            raise ValueError("Too many active task runs")
    for record in records:
        if (not isinstance(record, dict) or not isinstance(record.get("id"), str)
                or _finite_value(record.get("triggered_at")) is None or _finite_value(record.get("end")) is None
                or record.get("status") not in ("recording", "complete", "stopped")
                or not isinstance(record.get("points"), list) or len(record["points"]) > 211):
            raise ValueError("Invalid incident recording")
        for point in record["points"]:
            if (not isinstance(point, dict) or _finite_value(point.get("timestamp")) is None
                    or not isinstance(point.get("values"), dict) or not isinstance(point.get("processes"), list)
                    or len(point["processes"]) > 3 or not isinstance(point.get("errors"), list) or len(point["errors"]) > 8):
                raise ValueError("Invalid recording sample")
            if any(value is not None and _finite_value(value) is None for value in point["values"].values()):
                raise ValueError("Invalid recording value")
        record["_bytes"] = sum(len(json.dumps(point, ensure_ascii=False).encode("utf-8")) for point in record["points"])
    if len(json.dumps(records, ensure_ascii=False).encode("utf-8")) > 2*1024*1024:
        raise ValueError("Recording storage limit exceeded")


class JsonStore:
    """Atomic JSON store with one known-good backup and startup recovery."""

    def __init__(self, path):
        self.path = Path(path)
        self.backup_path = self.path.with_name(self.path.name + ".bak")
        self.lock = threading.RLock()
        self.recovered_from_backup = False
        self.persisted_retention_days = None
        self.last_compact_at = 0
        self.last_save_ms = None
        self.last_success_at = None
        self.write_failures = 0
        self.last_prune_at = 0
        self.dirty_days = {"*"}
        self.day_files = {}
        self.shard_readers = {}
        self.shard_cache = OrderedDict()
        self.shard_cache_bytes = 0
        self.last_encoded_days = 0
        self.encoded_bytes = self.path.stat().st_size if self.path.exists() else 0
        self._known_main_signature = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.data = self._load()
        self.persisted_retention_days = self._retention_days(self.data)
        cutoff = time.time() - self.persisted_retention_days * 24 * 60 * 60
        pruned = _prune_history_database(self.data, cutoff)
        compacted = _compact_history_database(self.data, time.time())
        self.last_compact_at = time.time()
        if not self.recovered_from_backup and self._valid_database_file(self.path):
            self._known_main_signature = self._file_signature(self.path)
        if self.recovered_from_backup or pruned or compacted:
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
        if not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] not in (1, 2):
            return None, ValueError("unsupported or invalid database schema")
        default = empty_database()
        default.update(value)
        try:
            _hydrate_history(default, path.with_name(path.name[:-4]) if path.name.endswith(".bak") else path)
            _validate_runtime_records(default)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
            return None, exc
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
        database, error = JsonStore._read_database(path)
        return database is not None and error is None

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

    def mark_history_dirty(self, stamp=None):
        self.dirty_days.add("*" if stamp is None else int(stamp)//86400)

    def history_window(self, identity, metric, start, end, shard_cache=None):
        return self.history_windows(identity, {metric}, start, end, shard_cache).get(metric, [])

    def history_windows(self, identity, metrics, start, end, shard_cache=None):
        """Snapshot dirty rows and pin immutable files before releasing the lock."""
        result = {metric: [] for metric in metrics}
        names = []
        with self.lock:
            resident = self.data.get("history", {}).get(identity, {})
            for day in range(int(start)//86400, int(end)//86400+1):
                name = self.day_files.get(day)
                if "*" in self.dirty_days or day in self.dirty_days or not name:
                    for metric in metrics:
                        points = resident.get(metric, [])
                        lower = bisect.bisect_left(points, day*86400, key=lambda point: point[0])
                        upper = bisect.bisect_left(points, (day+1)*86400, key=lambda point: point[0])
                        result[metric].extend(copy.deepcopy(points[lower:upper]))
                else:
                    names.append(name)
                    self.shard_readers[name] = self.shard_readers.get(name, 0)+1
        try:
            for name in names:
                records = shard_cache.get(name) if shard_cache is not None else None
                if records is None:
                    records = self._read_shard(name)
                    if shard_cache is not None:
                        shard_cache[name] = records
                for kind, node, field, point in records:
                    if kind == "host" and node == identity and field in metrics:
                        result[field].append(copy.deepcopy(point))
            for rows in result.values():
                rows.sort(key=lambda point: point[0])
            return result
        finally:
            self._unpin_shards(names)

    def _unpin_shards(self, names):
        with self.lock:
            for name in names:
                count = self.shard_readers[name]-1
                if count:
                    self.shard_readers[name] = count
                else:
                    del self.shard_readers[name]

    def _read_shard(self, name):
        with self.lock:
            cached = self.shard_cache.get(name)
            if cached is not None:
                self.shard_cache.move_to_end(name)
                return cached[0]
        directory = self.path.with_name(self.path.name + ".history")
        content = (directory/name).read_bytes()
        if hashlib.sha256(content).hexdigest() != name[11:-6]:
            raise ValueError("History shard checksum mismatch")
        records = [json.loads(line) for line in content.splitlines()]
        # Include a conservative allowance for decoded Python objects.
        cost = len(content)*8
        with self.lock:
            if name not in self.shard_cache and cost <= 32*1024*1024:
                while self.shard_cache and (len(self.shard_cache) >= 8 or self.shard_cache_bytes+cost > 32*1024*1024):
                    _, (_, removed) = self.shard_cache.popitem(last=False)
                    self.shard_cache_bytes -= removed
                self.shard_cache[name] = (records, cost)
                self.shard_cache_bytes += cost
        return records

    @contextmanager
    def backup_snapshot(self):
        """Flush and pin both generations for a consistent streaming archive."""
        with self.lock:
            self.save()
            indexes = {"data.json": self.path.read_bytes()}
            if self.backup_path.exists():
                indexes["data.json.bak"] = self.backup_path.read_bytes()
            names = set()
            for content in indexes.values():
                names.update(json.loads(content).get("history_files", []))
            for name in names:
                if not HISTORY_FILE_PATTERN.fullmatch(name):
                    raise ValueError("Invalid history manifest")
            for name in names:
                self.shard_readers[name] = self.shard_readers.get(name, 0)+1
        try:
            yield indexes, sorted(names)
        finally:
            self._unpin_shards(names)

    def export_backup(self, output):
        with self.backup_snapshot() as (indexes, names):
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                directory = self.path.with_name(self.path.name + ".history")
                sizes = [len(content) for content in indexes.values()]
                shard_sizes = [(directory/name).stat().st_size for name in names]
                if (len(names)+len(indexes)+1 > 750 or any(size > 8*1024*1024 for size in sizes)
                        or any(size > 128*1024*1024 for size in shard_sizes)
                        or sum(sizes)+sum(shard_sizes) > 512*1024*1024-4096):
                    raise ValueError("Backup exceeds the 512 MiB archive limit")
                for name, content in indexes.items():
                    archive.writestr(name, content)
                directory = self.path.with_name(self.path.name + ".history")
                for name in names:
                    archive.write(directory/name, "data.json.history/"+name)
                archive.writestr("backup.json", json.dumps({"format": 1, "created_at": int(time.time()),
                                                          "application": APP_NAME, "version": APP_VERSION}))

    def _encode_generation(self, database):
        """Re-encode dirty days; publish the index after their shard writes."""
        primary = database is self.data
        dirty = set(self.dirty_days) if primary else {"*"}
        files = dict(self.day_files) if primary else {}
        series = [("host", identity, metric, points) for identity, metrics in database.get("history", {}).items()
                  for metric, points in metrics.items() if points]
        series.extend(("service", identity, "latency", rows) for identity, rows in database.get("service_history", {}).items() if rows)
        if "*" in dirty:
            dirty = set(files)
            for kind, identity, metric, points in series:
                key = (lambda point: point[0]) if kind == "host" else (lambda point: point["bucket"])
                dirty.update(range(int(key(points[0]))//86400, int(key(points[-1]))//86400+1))
        directory = self.path.with_name(self.path.name + ".history")
        directory.mkdir(parents=True, exist_ok=True)
        for day in sorted(dirty):
            rows = []
            for kind, identity, metric, points in series:
                key = (lambda point: point[0]) if kind == "host" else (lambda point: point["bucket"])
                lower = bisect.bisect_left(points, day*86400, key=key)
                upper = bisect.bisect_left(points, (day+1)*86400, key=key)
                rows.extend([kind, identity, metric, point] for point in points[lower:upper])
            if not rows:
                files.pop(day, None)
                continue
            rows.sort(key=lambda row: (row[0], row[1], row[2], row[3][0] if row[0] == "host" else row[3]["bucket"]))
            content = ("\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True) for row in rows)+"\n").encode("utf-8")
            date = datetime.fromtimestamp(day*86400, timezone.utc).strftime("%Y-%m-%d")
            name = date + "-" + hashlib.sha256(content).hexdigest() + ".jsonl"
            target = directory/name
            if not target.exists():
                temporary = directory/(name+".tmp")
                self._write_synced(temporary, content)
                os.replace(temporary, target)
            files[day] = name
        if os.name != "nt" and dirty:
            descriptor = os.open(str(directory), os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        index = {key: value for key, value in database.items() if key not in ("history", "service_history", "history_files")}
        index.update(schema=2, history_files=[name for day, name in sorted(files.items())])
        if primary:
            self._pending_day_files = files
            self.last_encoded_days = len(dirty)
        return json.dumps(index, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def _cleanup_shards(self):
        """Delete only our named shards absent from both committed generations."""
        referenced = set(self.shard_readers)
        for path in (self.path, self.backup_path):
            if path.exists():
                with path.open(encoding="utf-8") as stream:
                    referenced.update(json.load(stream).get("history_files", []))
        directory = self.path.with_name(self.path.name + ".history")
        for path in directory.iterdir():
            if HISTORY_FILE_PATTERN.fullmatch(path.name) and path.name not in referenced:
                path.unlink()
                cached = self.shard_cache.pop(path.name, None)
                if cached:
                    self.shard_cache_bytes -= cached[1]

    def save(self, backup_retention_days=None):
        try:
            self._save_generation(backup_retention_days)
        except OSError:
            self.write_failures += 1
            raise

    def _save_generation(self, backup_retention_days=None):
        started = time.monotonic()
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + ".tmp")
            backup_temporary = self.backup_path.with_name(self.backup_path.name + ".tmp")
            encoded = self._encode_generation(self.data)
            self._write_synced(temporary, encoded)
            if self._main_is_known_good():
                if backup_retention_days is not None:
                    with self.path.open("r", encoding="utf-8") as current:
                        previous = _hydrate_history(json.load(current), self.path)
                    previous["history_retention_days"] = backup_retention_days
                    _prune_history_database(previous, time.time() - backup_retention_days * 24 * 60 * 60)
                    backup_content = self._encode_generation(previous)
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
            committed_signature = self._file_signature(temporary)
            os.replace(temporary, self.path)
            self._known_main_signature = committed_signature
            self.persisted_retention_days = self._retention_days(self.data)
            self.day_files = self._pending_day_files
            self.dirty_days.clear()
            self.data["schema"] = 2
            self._sync_parent_directory()
            self.encoded_bytes = len(encoded)
            self.last_save_ms = round((time.monotonic() - started) * 1000, 1)
            self.last_success_at = int(time.time())
            try:
                self._cleanup_shards()
            except (OSError, ValueError, TypeError):
                # Garbage collection is best effort; the committed index is valid.
                pass


BACKUP_LOCK = threading.Lock()


def restore_backup(archive_path, destination):
    """Validate an archive in a private directory, then publish a new data directory."""
    destination = Path(destination).absolute()
    parent = destination.parent
    if parent.exists() or not parent.parent.is_dir():
        raise ValueError("Restore requires a new data directory inside an existing parent directory")
    if destination.name in ("backup.json", "data.json.history") or not destination.name.endswith(".json"):
        raise ValueError("Use a .json database filename")
    with tempfile.TemporaryDirectory(prefix=".tinywatch-restore-", dir=parent.parent) as temporary:
        staging = Path(temporary)/"data"
        staging.mkdir(mode=0o700)
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            names = {entry.filename for entry in entries}
            if len(entries) > 750 or len(names) != len(entries) or sum(entry.file_size for entry in entries) > 512*1024*1024:
                raise ValueError("Backup exceeds limits or contains duplicate files")
            if not {"backup.json", "data.json"} <= names:
                raise ValueError("Backup index is missing")
            for entry in entries:
                name = entry.filename
                shard = name.removeprefix("data.json.history/")
                if name not in ("backup.json", "data.json", "data.json.bak") and not (
                        name.startswith("data.json.history/") and HISTORY_FILE_PATTERN.fullmatch(shard)):
                    raise ValueError("Unexpected backup filename")
                limit = 128*1024*1024 if name.startswith("data.json.history/") else 8*1024*1024
                if entry.file_size > limit or entry.flag_bits & 1:
                    raise ValueError("Oversized or encrypted backup entry")
                target = staging/name
                target.parent.mkdir(exist_ok=True, mode=0o700)
                with archive.open(entry) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=65536)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(target, 0o600)
        metadata = json.loads((staging/"backup.json").read_text(encoding="utf-8"))
        if not isinstance(metadata, dict) or type(metadata.get("format")) is not int or metadata["format"] != 1:
            raise ValueError("Unsupported backup format")
        referenced = set()
        for filename in ("data.json", "data.json.bak"):
            path = staging/filename
            if not path.exists():
                continue
            value, error = JsonStore._read_database(path)
            if error is not None or value is None:
                raise ValueError("Invalid backup database: "+filename)
            for field in ("history", "service_history", "alert_states", "service_states"):
                if not isinstance(value.get(field, {}), dict):
                    raise ValueError("Invalid backup database structure")
            for field in ("assets", "widgets", "alert_rules", "services", "heartbeats", "incidents", "timeline"):
                if not isinstance(value.get(field, []), list):
                    raise ValueError("Invalid backup database structure")
            index = json.loads(path.read_text(encoding="utf-8"))
            referenced.update("data.json.history/"+name for name in index.get("history_files", []))
        if names - {"backup.json", "data.json", "data.json.bak"} != referenced:
            raise ValueError("Backup manifest does not match its files")
        (staging/"backup.json").unlink()
        if destination.name != "data.json":
            for suffix in ("", ".bak", ".history"):
                source = staging/("data.json"+suffix)
                if source.exists():
                    source.rename(staging/(destination.name+suffix))
        if parent.exists():
            raise ValueError("Restore destination already exists")
        staging.rename(parent)
    return destination


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
    if value and "://" not in value:
        value = "http://" + value
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
                "flight_enabled": bool(STORE.data.get("flight_enabled", False)),
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


def _historical_last_success(asset_id):
    """Recover a node's last successful sample time after a service restart."""
    if STORE is None:
        return None
    with STORE.lock:
        history = STORE.data.get("history", {})
        series = history.get(asset_id, {}) if isinstance(history, dict) else {}
        if not isinstance(series, dict):
            return None
        timestamps = [int(_number(points[-1][0])) for points in series.values()
                      if isinstance(points, list) and points and isinstance(points[-1], list)
                      and points[-1] and _number(points[-1][0]) > 0]
    if not timestamps:
        return None
    try:
        return datetime.fromtimestamp(max(timestamps), timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def _bounded_network_probe(kind, configuration, timeout):
    """A disposable child gives DNS and response reads one wall-clock deadline."""
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--probe-worker", kind],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        output, _ = process.communicate(json.dumps(configuration).encode("utf-8"), timeout=timeout)
        if process.returncode != 0 or len(output) > 4_000_000:
            raise OSError("Probe worker failed")
        result = json.loads(output)
        if not isinstance(result, dict):
            raise ValueError("Invalid probe result")
        return result
    except BaseException:
        process.kill()
        process.communicate()
        raise


def _remote_snapshot(asset):
    started = time.monotonic()
    with REMOTE_STATUS_LOCK:
        previous = REMOTE_LAST_SUCCESS.get(asset["id"], {})
        last_success = previous.get("sampled_at") if previous.get("url") == asset["url"] else None
    last_success = last_success or _historical_last_success(asset["id"])
    try:
        result = _bounded_network_probe("asset", asset, 12)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        result = {"id": asset["id"], "name": asset["name"], "online": False, "metrics": None,
                  "error": "request_timeout", "latency_ms": round((time.monotonic()-started)*1000, 1)}
    if result.get("online"):
        with REMOTE_STATUS_LOCK:
            REMOTE_LAST_SUCCESS[asset["id"]] = {"url": asset["url"], "sampled_at": result.get("last_success_at")}
    else:
        result["last_success_at"] = last_success
    return result


def _remote_snapshot_direct(asset):
    asset_id = asset["id"]
    last_success_at = None
    with REMOTE_STATUS_LOCK:
        previous = REMOTE_LAST_SUCCESS.get(asset_id)
        if previous and previous.get("url") == asset["url"]:
            last_success_at = previous.get("sampled_at")
    if last_success_at is None:
        last_success_at = _historical_last_success(asset_id)
    request_started = time.monotonic()
    endpoint = asset["url"].rstrip("/") + "/api/agent/metrics"
    request = urllib.request.Request(endpoint, headers={"X-TinyWatch-Token": asset["password"],
                                                        "Accept": "application/json", "User-Agent": "TinyWatch/" + APP_VERSION})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirectHandler())
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise OSError("HTTP " + str(response.status))
            payload = response.read(2_000_000)
            data = json.loads(payload.decode("utf-8"))
            required_objects = ("info", "cpu", "memory", "disk", "network")
            if (not isinstance(data, dict)
                    or any(not isinstance(data.get(key), dict) for key in required_objects)
                    or not isinstance(data.get("load", []), list)
                    or not isinstance(data["network"].get("interfaces", []), list)
                    or not isinstance(data.get("processes", []), list)
                    or not isinstance(data.get("logins", []), list)
                    or not isinstance(data.get("dns", {}), dict)
                    or not isinstance(data.get("collector_errors", {}), dict)):
                raise ValueError("invalid metric response")
            for part in data["disk"].get("partitions", [])[:120]:
                if isinstance(part, dict):
                    part["id"] = _partition_id(part)
            try:
                sampled = datetime.fromisoformat(str(data.get("sampled_at", "")).replace("Z", "+00:00"))
                if sampled.tzinfo is None:
                    sampled = sampled.replace(tzinfo=timezone.utc)
                last_success_at = sampled.astimezone(timezone.utc).isoformat(timespec="seconds")
            except (TypeError, ValueError, OverflowError):
                last_success_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            with REMOTE_STATUS_LOCK:
                REMOTE_LAST_SUCCESS[asset_id] = {"url": asset["url"], "sampled_at": last_success_at}
            return {"id": asset_id, "name": asset["name"], "online": True,
                    "metrics": data, "last_success_at": last_success_at,
                    "latency_ms": round((time.monotonic() - request_started) * 1000, 1)}
    except Exception as exc:
        reason = getattr(exc, "reason", exc)
        return {"id": asset_id, "name": asset["name"], "online": False,
                "error": _safe_text(reason, 140), "metrics": None,
                "last_success_at": last_success_at,
                "latency_ms": round((time.monotonic() - request_started) * 1000, 1)}


def _point_metadata(point):
    """Optional trailing metadata keeps existing schema-1 numeric rows readable."""
    if len(point) > 2 and isinstance(point[-1], dict) and "resolution" in point[-1]:
        return point[-1]
    return {}


def _point_values(metric, point):
    if metric == "network":
        interfaces = point[1] if len(point) > 1 and isinstance(point[1], dict) else {}
        result = {"total": sum(sum(_number(value) for value in rates[:2])
                               for rates in interfaces.values() if isinstance(rates, list))}
        for name, rates in interfaces.items():
            if isinstance(rates, list):
                for index, value in enumerate(rates[:2]):
                    result[(name, index)] = _number(value)
        return result
    length = len(point) - (1 if _point_metadata(point) else 0)
    return {index: float(point[index]) for index in range(1, length)
            if isinstance(point[index], (int, float)) and math.isfinite(point[index])}


def _compact_history_database(database, now):
    """Compact older samples into 5-minute/hourly buckets, keeping extrema and gaps."""
    changed = False
    history = database.get("history", {})
    if not isinstance(history, dict):
        return False
    for series in history.values():
        if not isinstance(series, dict):
            continue
        for metric, points in list(series.items()):
            if not isinstance(points, list) or (metric not in ALERT_METRICS[:5] and metric != "disk_worst" and not metric.startswith("disk@")):
                continue
            groups, current, key, previous = [], [], None, None
            for point in points:
                if not isinstance(point, list) or len(point) < 2:
                    continue
                stamp = _number(point[0])
                resolution = 3600 if stamp < now - 7 * 86400 else (300 if stamp < now - 86400 else 60)
                metadata = _point_metadata(point)
                resolution = max(resolution, _number(metadata.get("resolution"), 60))
                gap = bool(metadata["gap_before"]) if "gap_before" in metadata else (
                    previous is not None and stamp - previous > HISTORY_GAP_SECONDS)
                group_key = (resolution, stamp // resolution)
                if current and (group_key != key or gap):
                    groups.append(current)
                    current = []
                values = point[:-1] if metadata else point[:]
                # Recent raw rows stay unchanged unless they mark a real gap.
                if resolution > 60 or gap:
                    values.append({"resolution": resolution, "gap_before": gap})
                current.append(values)
                key, previous = group_key, stamp
            if current:
                groups.append(current)
            retained = []
            for group in groups:
                if _point_metadata(group[0]).get("resolution", 60) == 60:
                    retained.extend(group)
                    continue
                selected = {0, len(group) - 1}
                dimensions = {}
                for index, point in enumerate(group):
                    for dimension, value in _point_values(metric, point).items():
                        dimensions.setdefault(dimension, []).append((value, index))
                for values in dimensions.values():
                    selected.add(min(values)[1])
                    selected.add(max(values)[1])
                retained.extend(group[index] for index in sorted(selected))
            if retained != points:
                _mark_replaced_rows(database, points, retained)
                series[metric] = retained
                changed = True
    # Context rows are bounded snapshots, not numeric chart samples.
    for series in history.values():
        if not isinstance(series, dict):
            continue
        rows = series.get("observations", [])
        buckets = {}
        for row in rows:
            if not isinstance(row, list) or len(row) != 2:
                continue
            stamp = _number(row[0])
            resolution = 3600 if stamp < now - 7 * 86400 else 300 if stamp < now - 86400 else 60
            key = (resolution, stamp // resolution)
            if key not in buckets:
                buckets[key] = [row]
            elif resolution > 60:
                buckets[key] = [buckets[key][0], row]
            else:
                buckets[key].append(row)
        retained = [row for bucket in buckets.values() for row in bucket]
        if retained != rows:
            _mark_replaced_rows(database, rows, retained)
            series["observations"] = retained
            changed = True
    return changed


def default_alert_rules():
    """Default rules evaluated by the minute sampler."""
    rules = []
    for metric, duration in (("cpu", 180), ("memory", 180), ("disk", 300), ("offline", 120)):
        rules.append({"id": "default-" + metric, "name": "", "node": "*", "metric": metric,
                      "mode": "threshold", "threshold": 0 if metric == "offline" else 90,
                      "recovery": 0 if metric == "offline" else 85, "duration": duration,
                      "cooldown": 300, "enabled": True})
    return rules


def _finite_value(value):
    if isinstance(value, bool):
        return None
    try:
        value = float(value)
        return value if math.isfinite(value) else None
    except (TypeError, ValueError, OverflowError):
        return None


def _sample_age(node, now):
    stamp = (node.get("metrics") or {}).get("sampled_at") or node.get("last_success_at")
    try:
        sampled = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if sampled.tzinfo is None:
            sampled = sampled.replace(tzinfo=timezone.utc)
        return round(now - sampled.timestamp(), 1)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _metric_value(node, metric, now, partition="*"):
    """Missing/failed measurements are unknown, never a zero or a recovery."""
    if node.get("pending"):
        return None
    if metric == "offline":
        return 0.0 if node.get("online") else 1.0
    if not node.get("online"):
        return None
    if metric == "stale":
        age = _sample_age(node, now)
        return max(0, age) if age is not None else None
    data = node.get("metrics") or {}
    age = _sample_age(node, now)
    if age is not None and (age > 120 or age < -120):
        return None
    if metric in data.get("collector_errors", {}):
        return None
    item = data.get(metric)
    if metric == "load":
        return _finite_value(item[0]) if isinstance(item, list) and item else None
    if not isinstance(item, dict) or item.get("supported") is False or item.get("available") is False:
        return None
    if metric == "network":
        rx, tx = _finite_value(item.get("rx_rate")), _finite_value(item.get("tx_rate"))
        return _finite_value(rx + tx) if rx is not None and tx is not None else None
    if metric == "disk":
        partitions = item.get("partitions", [])
        selected = [part for part in partitions if partition == "*" or
                    (part.get("id") or _partition_id(part)) == partition]
        values = [_finite_value(part.get("percent")) for part in selected]
        values = [value for value in values if value is not None]
        if values:
            return max(values)
        if partition != "*" or partitions:
            return None
        # Older agents without partition detail expose only aggregate usage.
    return _finite_value(item.get("percent"))


def _historical_value(metric, point):
    values = _point_values(metric, point)
    if metric == "network":
        return values.get("total")
    return values.get(3 if metric in ("memory", "disk", "disk_worst") or metric.startswith("disk@") else 1)


def _baseline_for(node_id, metric, now, minimum_delta):
    """Robust 24h baseline excluding the most recent 10 minutes of an incident."""
    history = STORE.data.get("history", {}).get(node_id, {}).get(metric, [])
    values = []
    for point in history:
        if not isinstance(point, list) or not point or not now - 86400 <= _number(point[0]) <= now - 600:
            continue
        # Extreme-point retention is intentionally biased toward peaks. Use only
        # raw minute rows for statistical baselines, never compacted extrema.
        if _point_metadata(point).get("resolution", 60) > 60:
            continue
        value = _historical_value(metric, point)
        if value is not None and math.isfinite(value):
            values.append(value)
    return _baseline_values(values, minimum_delta)


def _baseline_values(values, minimum_delta):
    if len(values) < 30:
        return None
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    delta = max(minimum_delta, 3 * 1.4826 * mad)
    if not all(math.isfinite(value) for value in (median, mad, delta, median + delta)):
        return None
    return {"median": round(median, 3), "mad": round(mad, 3), "samples": len(values),
            "threshold": round(median + delta, 3), "recovery": round(median + delta * .7, 3),
            "window_seconds": 86400, "excluded_seconds": 600}


def _validate_alert_rules(value, valid_nodes):
    if not isinstance(value, list) or len(value) > MAX_ALERT_RULES:
        raise ValueError("Alert rules must be a list of at most 32 rules")
    rules, identifiers = [], set()
    for raw in value:
        if not isinstance(raw, dict):
            raise ValueError("Invalid alert rule")
        rule_id = raw.get("id", "")
        node_id, metric = raw.get("node"), raw.get("metric")
        mode = raw.get("mode", "threshold")
        if (not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", rule_id)
                or rule_id in identifiers or not isinstance(node_id, str) or node_id not in valid_nodes | {"*"}
                or not isinstance(metric, str) or metric not in ALERT_METRICS
                or not isinstance(mode, str) or mode not in ("threshold", "baseline")):
            raise ValueError("Invalid rule identity, node, metric or mode")
        if metric in ("offline", "stale") and mode != "threshold":
            raise ValueError("Availability rules require threshold mode")
        threshold, recovery = _finite_value(raw.get("threshold")), _finite_value(raw.get("recovery"))
        duration, cooldown = _finite_value(raw.get("duration")), _finite_value(raw.get("cooldown"))
        if (threshold is None or recovery is None or threshold < 0 or recovery < 0
                or duration is None or cooldown is None or not 0 <= duration <= 86400
                or not 0 <= cooldown <= 7 * 86400 or duration != int(duration) or cooldown != int(cooldown)
                or (mode == "threshold" and recovery > threshold)
                or (mode == "baseline" and threshold <= 0)):
            raise ValueError("Invalid thresholds, duration or cooldown")
        if metric == "offline" and (threshold != 0 or recovery != 0):
            raise ValueError("Offline rules use threshold and recovery 0")
        if metric in ("cpu", "memory", "disk") and max(threshold, recovery) > 100:
            raise ValueError("Percentage thresholds must not exceed 100")
        name, enabled = raw.get("name", ""), raw.get("enabled", True)
        if not isinstance(name, str) or len(name) > 80 or not isinstance(enabled, bool):
            raise ValueError("Invalid rule name or enabled flag")
        partition = raw.get("partition", "*")
        if not isinstance(partition, str) or (partition != "*" and not re.fullmatch(r"[a-f0-9]{24}", partition)):
            raise ValueError("Invalid partition identity")
        if metric != "disk" and partition != "*":
            raise ValueError("Partition selection requires a disk rule")
        if partition != "*" and node_id == "*":
            raise ValueError("A partition rule requires a specific asset")
        identifiers.add(rule_id)
        rules.append({"id": rule_id, "name": name.strip(), "node": node_id, "metric": metric,
                      "mode": mode, "threshold": threshold, "recovery": recovery,
                      "duration": int(duration), "cooldown": int(cooldown), "enabled": enabled, "partition": partition})
    return rules


PREVIEW_LOCK = threading.Lock()


def _preview_series(rule, points, start, end):
    events, missing = [], []
    pending, active, recovered = None, None, -math.inf
    previous, previous_known, known_seconds = start, False, 0
    stamps = [point[0] for point in points]
    for point in points:
        stamp = point[0]
        if stamp < start or stamp > end:
            continue
        raw = _point_metadata(point).get("resolution", 60) <= 60
        value = _historical_value(rule["history_metric"], point) if raw else None
        baseline = None
        if rule["mode"] == "baseline" and value is not None:
            if active:
                baseline = active["baseline"]
            else:
                lo = bisect.bisect_left(stamps, stamp-86400)
                hi = bisect.bisect_right(stamps, stamp-600)
                values = [_historical_value(rule["history_metric"], row) for row in points[lo:hi]
                          if _point_metadata(row).get("resolution", 60) <= 60]
                values = [item for item in values if item is not None and math.isfinite(item)]
                baseline = _baseline_values(values, rule["threshold"])
            if baseline is None:
                value = None
        threshold = baseline["threshold"] if baseline else rule["threshold"]
        recovery = baseline["recovery"] if baseline else rule["recovery"]
        gap = stamp-previous > HISTORY_GAP_SECONDS or bool(_point_metadata(point).get("gap_before"))
        valid = value is not None and math.isfinite(value)
        contiguous = valid and previous_known and not gap
        if contiguous:
            known_seconds += stamp-previous
            if active:
                active["observed_seconds"] += stamp-previous
        elif stamp > previous:
            if len(missing) < 200:
                if missing and missing[-1][1] == previous:
                    missing[-1][1] = stamp
                else:
                    missing.append([previous, stamp])
            if active:
                active["uncertain"] = True
        if gap or not valid:
            pending = None
        previous, previous_known = stamp, valid
        if not valid:
            continue
        if active:
            active["peak"] = max(active["peak"], value)
            if value <= recovery:
                active["resolved_at"] = stamp
                active["elapsed_seconds"] = stamp-active["triggered_at"]
                recovered, active = stamp, None
            continue
        if value <= threshold or stamp-recovered < rule["cooldown"]:
            pending = None
            continue
        if pending is None:
            pending = stamp
        if stamp-pending < rule["duration"]:
            continue
        active = {"started_at": pending, "triggered_at": stamp, "resolved_at": None,
                  "threshold": threshold, "recovery": recovery, "peak": value,
                  "baseline": baseline, "observed_seconds": 0, "uncertain": False}
        events.append(active)
        pending = None
    if previous < end and len(missing) < 200:
        missing.append([previous, end])
        if active:
            active["uncertain"] = True
    for event in events:
        event.setdefault("elapsed_seconds", end-event["triggered_at"])
    return {"count": len(events), "events": events[-200:], "known_seconds": round(known_seconds),
            "unknown_seconds": max(0, round(end-start-known_seconds)), "unknown_ranges": missing,
            "events_truncated": len(events) > 200, "ranges_truncated": len(missing) >= 200}


def _preview_rule(value):
    now = time.time()
    with STORE.lock:
        valid_nodes = {"local"} | {asset["id"] for asset in STORE.data.get("assets", [])}
        rule = _validate_alert_rules([value.get("rule")], valid_nodes)[0]
        start = _finite_value(value.get("start", max(now-7*86400, now-_history_retention_seconds())))
        end = _finite_value(value.get("end", now))
        if start is None or end is None or not now-_history_retention_seconds() <= start < end <= now or end-start > 7*86400:
            raise ValueError("Choose an interval within retention and no longer than seven days")
        if rule["metric"] in ("offline", "stale"):
            raise ValueError("Offline and stale rules have no recorded decision history")
        metric = rule["metric"]
        if metric == "disk":
            metric = "disk_worst" if rule["partition"] == "*" else "disk@"+rule["partition"]
        rule["history_metric"] = metric
        identities = sorted(valid_nodes) if rule["node"] == "*" else [rule["node"]]
    shards = {}
    histories = {identity: STORE.history_window(identity, metric, start-86400, end, shards) for identity in identities}
    raw_count = sum(sum(start <= row[0] <= end and _point_metadata(row).get("resolution", 60) <= 60
                        for row in rows) for rows in histories.values())
    if raw_count > (3000 if rule["mode"] == "baseline" else 80000):
        raise ValueError("Preview is too large; choose one asset or a shorter interval")
    reports = []
    for identity, points in histories.items():
        report = _preview_series(rule, points, start, end) if rule["enabled"] else {
            "count": 0, "events": [], "known_seconds": 0, "unknown_seconds": round(end-start), "unknown_ranges": [[start, end]]}
        limit = max(1, 200//len(identities))
        report["events_truncated"] = report.get("events_truncated", False) or len(report["events"]) > limit
        report["events"] = report["events"][-limit:]
        reports.append(dict(report, node=identity))
    return {"start": start, "end": end, "reports": reports, "count": sum(report["count"] for report in reports),
            "enabled": rule["enabled"], "raw_only": True}


def _capacity_estimate(points, now):
    rows = [point for point in points if len(point) >= 4 and now-7*86400 <= point[0] <= now
            and all(_finite_value(item) is not None for item in point[:4]) and 0 <= point[1] <= point[2] <= 2**80 and point[2] > 0]
    result = {"days_remaining": None, "growth_per_day": None, "samples": len(rows), "status": "insufficient"}
    if not rows:
        return result
    if now-rows[-1][0] > 300:
        return dict(result, status="stale")
    if any(point[2] != rows[-1][2] for point in rows):
        return dict(result, status="capacity_changed")
    if any(right[0]-left[0] > 6*3600 for left, right in zip(rows, rows[1:])):
        return dict(result, status="data_gap")
    days = {}
    for point in rows:
        day = int(point[0])//86400
        entry = days.setdefault(day, {"hours": set(), "last": point})
        entry["hours"].add(int(point[0])//3600)
        entry["last"] = point
    daily = [entry["last"] for day, entry in sorted(days.items()) if len(entry["hours"]) >= 12]
    if len(daily) < 4 or daily[-1][0]-daily[0][0] < 3*86400:
        return result
    slopes = [(right[1]-left[1])*86400/(right[0]-left[0])
              for i, left in enumerate(daily) for right in daily[i+1:]]
    slope = statistics.median(slopes)
    result.update(growth_per_day=round(slope), span_days=round((daily[-1][0]-daily[0][0])/86400, 1))
    if slope <= 0:
        return dict(result, status="no_growth")
    mad = statistics.median(abs(value-slope) for value in slopes)
    origin = daily[0][0]
    intercept = statistics.median(point[1]-slope*(point[0]-origin)/86400 for point in daily)
    mean = statistics.mean(point[1] for point in daily)
    variation = sum((point[1]-mean)**2 for point in daily)
    residual = sum((point[1]-(intercept+slope*(point[0]-origin)/86400))**2 for point in daily)
    fit = 1-residual/variation if variation else 0
    result["fit"] = round(max(0, fit), 3)
    if mad > slope*.5 or fit < .7:
        return dict(result, status="unstable")
    remaining = max(0, rows[-1][2]-rows[-1][1])/slope
    if remaining > 365:
        return dict(result, status="long_horizon")
    return dict(result, status="estimated", days_remaining=round(remaining, 1), last_sample_at=rows[-1][0])


def _capacity_forecasts(identity):
    now = time.time()
    with STORE.lock:
        valid = {"local"} | {asset["id"] for asset in STORE.data.get("assets", [])}
        if identity not in valid:
            raise ValueError("Unknown asset")
        metrics = {metric for metric in STORE.data.get("history", {}).get(identity, {}) if metric.startswith("disk@")}
        if len(metrics) > 120:
            metrics = set(sorted(metrics)[:120])
        lower = max(now-7*86400, now-_history_retention_seconds())
    history = STORE.history_windows(identity, metrics, lower, now)
    return {"node": identity, "sampled_at": int(now),
            "partitions": {metric[5:]: _capacity_estimate(rows, now) for metric, rows in history.items()}}


def _incident_context(node):
    """Capture bounded process and login context for an incident."""
    metrics = node.get("metrics") or {}
    processes = sorted([item for item in metrics.get("processes", []) if isinstance(item, dict)],
                       key=lambda item: _finite_value(item.get("cpu")) or 0, reverse=True)[:3]
    return {"processes": [{"pid": _number(item.get("pid")), "name": _safe_text(item.get("name"), 80),
                           "cpu": _finite_value(item.get("cpu")), "memory": _number(item.get("memory")),
                           "started": item.get("started")}
                          for item in processes],
            "logins": [{"kind": _safe_text(item.get("kind"), 40),
                        "message": _safe_text(item.get("message"), 180)}
                       for item in metrics.get("logins", [])[:3] if isinstance(item, dict)],
            "dns": {"count": _number((metrics.get("dns") or {}).get("count")),
                    "source": _safe_text((metrics.get("dns") or {}).get("source"), 80)},
            "collector_errors": {str(key)[:30]: _safe_text(value, 180)
                                 for key, value in metrics.get("collector_errors", {}).items()},
            "connection_error": _safe_text(node.get("error"), 180),
            "sampled_at": metrics.get("sampled_at"),
            "capabilities": {name: bool(metrics.get(name)) and name not in metrics.get("collector_errors", {})
                             and metrics[name].get("supported", True) and metrics[name].get("available", True)
                             for name in ("cpu", "memory", "disk", "network") if isinstance(metrics.get(name), dict)},
            "collector_status": {name: copy.deepcopy(entry) for name, entry in
                                 metrics.get("collector_status", {}).items() if name in ("processes", "logins", "dns")}}


FLIGHT_LOCK = threading.Lock()
FLIGHT_RING = deque(maxlen=150)
FLIGHT_RING_BYTES = 0


def _flight_sample(metrics):
    node = {"online": True, "metrics": metrics}
    now = time.time()
    age = _sample_age(node, now)
    if age is None or not 0 <= age <= 10:
        return None
    context = _incident_context(node)
    processes = [dict(item, name=_safe_text(item["name"], 64)) for item in context["processes"]]
    row = {"timestamp": int(now-age), "values": {metric: _metric_value(node, metric, now)
           for metric in ("cpu", "memory", "disk", "network", "load")}, "processes": processes,
           "process_sample_at": metrics.get("collector_status", {}).get("processes", {}).get("sampled_at"),
           "errors": list(metrics.get("collector_errors", {}))[:8]}
    if len(json.dumps(row, ensure_ascii=False).encode("utf-8")) > 2048:
        row["processes"], row["errors"] = [], []
    return row


def _limit_flight_records(now):
    rows = STORE.data.setdefault("flight_records", [])
    cutoff = now-_history_retention_seconds()
    rows[:] = [row for row in rows if row["triggered_at"] >= cutoff]
    while rows and (len(rows) > 16 or sum((row["_bytes"] if "_bytes" in row else sum(len(json.dumps(point, ensure_ascii=False).encode("utf-8")) for point in row.get("points", []))) for row in rows) > 1_800_000):
        rows.pop(0)


def _start_flight_record(incident):
    """Called under the data lock; remote incidents keep their ordinary context."""
    if incident["node"] != "local" or not STORE.data.get("flight_enabled"):
        return
    now = incident["triggered_at"]
    with FLIGHT_LOCK:
        points = [copy.deepcopy(point) for point, size in FLIGHT_RING if now-300 <= point["timestamp"] <= now]
    record = {"id": incident["id"], "triggered_at": now, "end": now+120, "status": "recording", "points": points,
              "interval": 2, "_bytes": sum(len(json.dumps(point, ensure_ascii=False).encode("utf-8")) for point in points)}
    STORE.data.setdefault("flight_records", []).append(record)
    _limit_flight_records(now)


def _flight_sampler(stop_event):
    """Reuse cached collectors; persist incident clips at most every thirty seconds."""
    global FLIGHT_RING_BYTES
    last_save, dirty = time.monotonic(), False
    try:
        while not stop_event.is_set():
            _worker_tick("flight")
            with STORE.lock:
                enabled = bool(STORE.data.get("flight_enabled"))
            row = _flight_sample(collect_snapshot()) if enabled else None
            if row:
                size = len(json.dumps(row, ensure_ascii=False).encode("utf-8"))
                with FLIGHT_LOCK:
                    if not FLIGHT_RING or row["timestamp"] > FLIGHT_RING[-1][0]["timestamp"]:
                        if len(FLIGHT_RING) == FLIGHT_RING.maxlen:
                            FLIGHT_RING_BYTES -= FLIGHT_RING[0][1]
                        FLIGHT_RING.append((row, size))
                        FLIGHT_RING_BYTES += size
                        while FLIGHT_RING_BYTES > 300_000:
                            FLIGHT_RING_BYTES -= FLIGHT_RING.popleft()[1]
            elif not enabled:
                with FLIGHT_LOCK:
                    FLIGHT_RING.clear()
                    FLIGHT_RING_BYTES = 0
            now = int(time.time())
            with STORE.lock:
                for record in STORE.data.get("flight_records", []):
                    if record["status"] != "recording":
                        continue
                    if not enabled or now > record["end"]:
                        record["status"] = "complete" if enabled else "stopped"
                        dirty = True
                    elif row and row["timestamp"] >= record["triggered_at"] and (
                            not record["points"] or row["timestamp"] > record["points"][-1]["timestamp"]):
                        record["points"].append(copy.deepcopy(row))
                        record["_bytes"] += size
                        if len(record["points"]) > 211:
                            removed = record["points"].pop(0)
                            record["_bytes"] -= len(json.dumps(removed, ensure_ascii=False).encode("utf-8"))
                        dirty = True
                previous_ids = [record["id"] for record in STORE.data.get("flight_records", [])]
                _limit_flight_records(now)
                dirty = dirty or previous_ids != [record["id"] for record in STORE.data.get("flight_records", [])]
                if dirty and time.monotonic()-last_save >= 30:
                    try:
                        STORE.save()
                        last_save, dirty = time.monotonic(), False
                    except OSError:
                        pass
            stop_event.wait(2)
    finally:
        with STORE.lock:
            for record in STORE.data.get("flight_records", []):
                if record["status"] == "recording":
                    record["status"] = "stopped"
                    dirty = True
            if dirty:
                try:
                    STORE.save()
                except OSError:
                    sys.stderr.write("TinyWatch incident recorder: database write failed\n")


def _flight_response(identity):
    with STORE.lock:
        record = next((row for row in STORE.data.get("flight_records", []) if row["id"] == identity), None)
        if record is None:
            raise ValueError("No retained flight record")
        result = copy.deepcopy(record)
    result.pop("_bytes", None)
    points = result["points"]
    result["start"] = result["triggered_at"]-300
    covered = sum(right["timestamp"]-left["timestamp"] for left, right in zip(points, points[1:])
                  if 0 < right["timestamp"]-left["timestamp"] <= 5)
    result["coverage"] = round(min(1, covered/420)*100, 1)
    result["gaps"] = [[left["timestamp"], right["timestamp"]] for left, right in zip(points, points[1:])
                      if right["timestamp"]-left["timestamp"] > 5]
    if not points:
        result["gaps"] = [[result["start"], result["end"]]]
    else:
        if points[0]["timestamp"] > result["start"]:
            result["gaps"].insert(0, [result["start"], points[0]["timestamp"]])
        if points[-1]["timestamp"] < result["end"]:
            result["gaps"].append([points[-1]["timestamp"], result["end"]])
    return result


def _alert_partition_mount(node, rule):
    if rule["metric"] != "disk":
        return ""
    parts = (node.get("metrics") or {}).get("disk", {}).get("partitions", [])
    selected = [part for part in parts if rule.get("partition", "*") == "*" or
                (part.get("id") or _partition_id(part)) == rule["partition"]]
    return _safe_text(max(selected, key=lambda part: _number(part.get("percent"))).get("mount"), 256) if selected else ""


def _resolve_incident(incident, now, reason):
    incident.update(status="resolved", resolved_at=int(now), resolution_reason=reason)
    _queue_notification(incident, "resolved", now)


def _evaluate_alerts(nodes, now):
    """Advance pending/active incidents; missing measurements cannot resolve them."""
    states = STORE.data.setdefault("alert_states", {})
    incidents = STORE.data.setdefault("incidents", [])
    active = {item["id"]: item for item in incidents if item.get("status") == "active"}
    valid_keys = set()
    for rule in STORE.data.get("alert_rules", []):
        if not rule.get("enabled"):
            continue
        targets = nodes.items() if rule["node"] == "*" else [(rule["node"], nodes.get(rule["node"]))]
        for node_id, node in targets:
            if node is None:
                continue
            key = rule["id"] + ":" + node_id
            valid_keys.add(key)
            state = states.setdefault(key, {})
            incident = active.get(state.get("active_id"))
            value = _metric_value(node, rule["metric"], now, rule.get("partition", "*"))
            baseline = None
            if incident:
                # Keep an active incident's baseline fixed until recovery.
                baseline = incident.get("baseline")
            elif rule["mode"] == "baseline":
                history_metric = rule["metric"]
                if history_metric == "disk":
                    history_metric = "disk_worst" if rule.get("partition", "*") == "*" else "disk@" + rule["partition"]
                baseline = _baseline_for(node_id, history_metric, now, rule["threshold"])
            threshold = baseline["threshold"] if baseline else rule["threshold"]
            recovery = baseline["recovery"] if baseline else rule["recovery"]
            last_observation = state.get("observed_at", now)
            state["observed_at"] = now
            if value is None or (rule["mode"] == "baseline" and baseline is None):
                state.pop("pending_since", None)
                state["evaluation"] = "warming_up" if value is not None else "unavailable"
                continue
            state["evaluation"] = "ready"
            if incident:
                incident["last_value"] = value
                incident["last_observed_at"] = int(now)
                incident["peak"] = max(incident["peak"], value)
                if value <= recovery:
                    _resolve_incident(incident, now, "recovered")
                    state.pop("active_id", None)
                    state["recovered_at"] = now
                continue
            if value <= threshold:
                state.pop("pending_since", None)
                continue
            if now - last_observation > HISTORY_GAP_SECONDS:
                state.pop("pending_since", None)
            if now - state.get("recovered_at", 0) < rule["cooldown"]:
                state.pop("pending_since", None)
                continue
            pending = state.setdefault("pending_since", now)
            if now - pending < rule["duration"]:
                continue
            incident = {"id": uuid.uuid4().hex, "rule_id": rule["id"], "rule_name": rule["name"],
                        "node": node_id, "node_name": _safe_text(node.get("name") or node_id, 80),
                        "metric": rule["metric"], "mode": rule["mode"], "status": "active",
                        "started_at": int(pending), "triggered_at": int(now), "resolved_at": None,
                        "acknowledged_at": None, "threshold": threshold, "recovery": recovery,
                        "duration": rule["duration"], "value": value, "last_value": value,
                        "peak": value, "last_observed_at": int(now), "baseline": baseline,
                        "context": _incident_context(node), "partition": rule.get("partition", "*"),
                        "partition_mount": _alert_partition_mount(node, rule)}
            incidents.append(incident)
            _start_flight_record(incident)
            _queue_notification(incident, "active", now)
            state["active_id"] = incident["id"]
            state.pop("pending_since", None)
    for key in list(states):
        if key not in valid_keys:
            incident = active.get(states[key].get("active_id"))
            if incident:
                _resolve_incident(incident, now, "rule_removed")
            del states[key]
    # Active incidents are bounded by rules x nodes and must never be evicted.
    resolved = [item for item in incidents if item.get("status") != "active"]
    active_items = [item for item in incidents if item.get("status") == "active"]
    room = max(0, MAX_INCIDENTS - len(active_items))
    STORE.data["incidents"] = sorted(active_items + (resolved[-room:] if room else []),
                                     key=lambda item: item["triggered_at"])


def _alerts_response():
    with STORE.lock:
        incidents = STORE.data.get("incidents", [])
        return copy.deepcopy({"rules": STORE.data.get("alert_rules", []), "states": STORE.data.get("alert_states", {}),
                "flight_ids": [row["id"] for row in STORE.data.get("flight_records", [])],
                "incidents": list(reversed(incidents)), "sample_interval": HISTORY_INTERVAL,
                "active_count": sum(item.get("status") == "active" for item in incidents),
                "unacknowledged_count": sum(item.get("status") == "active" and not item.get("acknowledged_at")
                                            for item in incidents)})


def _alert_counts():
    with STORE.lock:
        active = [item for item in STORE.data.get("incidents", []) if item.get("status") == "active"]
        return {"active_count": len(active),
                "unacknowledged_count": sum(not item.get("acknowledged_at") for item in active)}


def _configuration_candidate(previous):
    """History rows are immutable here; config changes replace or remove series."""
    candidate = {key: copy.deepcopy(value) for key, value in previous.items()
                 if key not in ("history", "service_history")}
    candidate["history"] = {identity: dict(series) for identity, series in previous.get("history", {}).items()}
    candidate["service_history"] = dict(previous.get("service_history", {}))
    return candidate


def _save_alert_rules(value):
    with STORE.lock:
        previous = STORE.data
        STORE.data = _configuration_candidate(previous)
        try:
            return _apply_alert_rules(value)
        except Exception:
            STORE.data = previous
            raise


def _apply_alert_rules(value):
    with STORE.lock:
        valid_nodes = {"local"} | {asset["id"] for asset in STORE.data.get("assets", [])}
        rules = _validate_alert_rules(value, valid_nodes)
        previous = {rule["id"]: rule for rule in STORE.data.get("alert_rules", [])}
        current = {rule["id"]: rule for rule in rules}
        changed = {key for key in previous if previous[key] != current.get(key)}
        for incident in STORE.data.get("incidents", []):
            if incident.get("status") == "active" and incident.get("rule_id") in changed:
                _resolve_incident(incident, time.time(), "rule_changed")
        states = STORE.data.get("alert_states", {})
        STORE.data["alert_states"] = {key: item for key, item in states.items()
                                      if key.split(":", 1)[0] not in changed}
        STORE.data["alert_rules"] = rules
        STORE.save()


def _acknowledge_incident(incident_id):
    with STORE.lock:
        for incident in STORE.data.get("incidents", []):
            if incident["id"] == incident_id:
                if not incident.get("acknowledged_at"):
                    incident["acknowledged_at"] = int(time.time())
                    STORE.save()
                return True
    return False


def _limit_history_points(rows, gaps, metric, maximum=1200):
    """Bound JSON responses while retaining extrema and explicit outage breaks."""
    if len(rows) <= maximum:
        return rows, gaps
    boundaries = [index for index, gap in enumerate(gaps) if gap and index > 0]
    stride = max(1, math.ceil(len(boundaries) / (maximum // 4)))
    selected = {0, len(rows) - 1}
    for index in boundaries[::stride]:
        selected.update((index - 1, index))
    dimensions = 3 if metric == "network" else 1
    bucket_count = max(1, (maximum - len(selected)) // (2 * dimensions))
    for bucket in range(bucket_count):
        start = bucket * len(rows) // bucket_count
        end = (bucket + 1) * len(rows) // bucket_count
        def values(index):
            row = rows[index]
            return ((row[1] + row[2], row[1], row[2]) if metric == "network" else
                    (row[3] if metric in ("memory", "disk") else row[1],))
        for dimension in range(dimensions):
            selected.add(min(range(start, end), key=lambda index: values(index)[dimension]))
            selected.add(max(range(start, end), key=lambda index: values(index)[dimension]))
    indices = sorted(selected)
    prefix = [0]
    for gap in gaps:
        prefix.append(prefix[-1] + bool(gap))
    selected_gaps = [bool(gaps[indices[0]])]
    selected_gaps.extend(prefix[right + 1] > prefix[left + 1] for left, right in zip(indices, indices[1:]))
    return [rows[index] for index in indices], selected_gaps


def _diagnostics_response(snapshot, now=None):
    now = time.time() if now is None else now
    reports = []
    for node_id, node in snapshot.get("nodes", {}).items():
        issues, metrics = [], node.get("metrics") or {}
        age = _sample_age(node, now)
        if node.get("pending"):
            status = "initializing"
        elif not node.get("online"):
            status = "connection_failed"
        elif age is None or age > 120:
            status = "stale"
        else:
            status = "healthy"
        if age is not None and age < -120:
            issues.append({"metric": "info", "kind": "clock_skew", "message": ""})
        errors = metrics.get("collector_errors", {})
        for metric, error in errors.items():
            issues.append({"metric": str(metric)[:30], "kind": "error", "message": _safe_text(error, 180)})
        if node.get("online"):
            for metric in ("cpu", "memory", "disk", "network", "load"):
                item = metrics.get(metric)
                supported = (bool(item) if metric == "load" else isinstance(item, dict)
                             and item.get("supported", True) and item.get("available", True))
                if not supported and metric not in errors:
                    issues.append({"metric": metric, "kind": "unsupported", "message": ""})
            if status == "healthy" and issues:
                status = "partial"
        reports.append({"id": node_id, "name": node.get("name") or node_id, "status": status,
                        "age_seconds": age, "last_success_at": node.get("last_success_at") or metrics.get("sampled_at"),
                        "latency_ms": node.get("latency_ms"), "issues": issues,
                        "error": "" if node.get("pending") else _safe_text(node.get("error"), 180),
                        "retry_seconds": node.get("retry_seconds"), "received_at": node.get("received_at"),
                        "next_retry_at": node.get("next_retry_at"), "consecutive_failures": node.get("consecutive_failures", 0),
                        "platform": _safe_text((metrics.get("info") or {}).get("os"), 40),
                        "collectors": copy.deepcopy(metrics.get("collector_status", {}))})
    return {"runtime": _runtime_health(now), "nodes": reports, "sampled_at": snapshot.get("sampled_at"),
            "history_interval": HISTORY_INTERVAL, "cache_seconds": CLUSTER_CACHE_SECONDS,
            "asset_limit": MAX_ASSETS, "rule_limit": MAX_ALERT_RULES,
            "storage": {"bytes": getattr(STORE, "encoded_bytes", 0), "last_write_ms": getattr(STORE, "last_save_ms", None), "encoded_days": STORE.last_encoded_days}}


def _record_history(nodes, now=None):
    """Persist a compact cluster sample at most once per minute."""
    global HISTORY_LAST_WRITE
    if STORE is None:
        return
    now = time.time() if now is None else now
    with STORE.lock:
        if now - HISTORY_LAST_WRITE < HISTORY_INTERVAL:
            return
        _evaluate_alerts(nodes, now)
        history = STORE.data.setdefault("history", {})
        if not isinstance(history, dict):
            history = STORE.data["history"] = {}
        cutoff = now - _history_retention_seconds()
        for node_id, node in nodes.items():
            metrics = node.get("metrics") if node.get("online") else None
            if not isinstance(metrics, dict):
                continue
            age = _sample_age(node, now)
            if age is not None and (age > 120 or age < -120):
                continue
            sample_time = int(now - (age or 0))
            series = history.setdefault(str(node_id), {})
            if not isinstance(series, dict):
                series = history[str(node_id)] = {}
            observations = series.get("observations", [])
            if observations and sample_time <= observations[-1][0]:
                continue
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
                "cpu": [round(_finite_value(cpu.get("percent")) or 0, 2)],
                "memory": [round(_number(memory.get("used"))), round(_number(memory.get("total"))),
                           round(_finite_value(memory.get("percent")) or 0, 2)],
                "disk": [round(_number(disk.get("used"))), round(_number(disk.get("total"))),
                         round(_finite_value(disk.get("percent")) or 0, 2)],
                "network": [interfaces],
                "load": [round(_finite_value(value) or 0, 3) for value in load[:3]],
            }
            if disk.get("supported", True) and "disk" not in metrics.get("collector_errors", {}):
                partitions = disk.get("partitions", [])[:120]
                for part in partitions:
                    part_id = part.get("id") or _partition_id(part)
                    samples["disk@" + part_id] = [round(_number(part.get("used"))), round(_number(part.get("total"))),
                                                   round(_number(part.get("percent")), 2)]
                if partitions:
                    worst = max(partitions, key=lambda part: _number(part.get("percent")))
                    samples["disk_worst"] = [round(_number(worst.get("used"))), round(_number(worst.get("total"))),
                                              round(_number(worst.get("percent")), 2)]
            collector_errors = metrics.get("collector_errors", {})
            if not isinstance(collector_errors, dict):
                collector_errors = {}
            metric_available = {"cpu": cpu.get("available", True),
                                "memory": memory.get("supported", True),
                                "disk": disk.get("supported", True),
                                "network": network.get("supported", True),
                                "load": bool(load)}
            for metric, values in samples.items():
                if (metric in collector_errors or not metric_available.get(metric, True)
                        or _metric_value(node, "disk" if metric.startswith("disk@") or metric == "disk_worst" else metric, now) is None):
                    continue
                points = series.setdefault(metric, [])
                if not isinstance(points, list):
                    points = series[metric] = []
                row = [sample_time] + values
                if (metric in ("memory", "disk", "disk_worst") or metric.startswith("disk@")) and points and len(points[-1]) > 2 and points[-1][2] != values[1]:
                    # A resize changes the denominator; start a new chart segment.
                    row.append({"resolution": 60, "gap_before": True})
                points.append(row)
            series.setdefault("observations", []).append([sample_time, _incident_context(node)])
            STORE.mark_history_dirty(sample_time)
            _record_node_changes(node_id, node, now)
        _prune_history_database(STORE.data, cutoff)
        if now - STORE.last_compact_at >= HISTORY_COMPACT_INTERVAL:
            _compact_history_database(STORE.data, now)
            STORE.last_compact_at = now
        STORE.save()
        HISTORY_LAST_WRITE = now


def _history_response(node_id, metric, range_name, interface="", start=None, end=None, partition=""):
    history_metric = "disk@" + partition if metric == "disk" and partition else metric
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
    points = STORE.history_window(node_id, history_metric, lower_bound-86400, upper_bound)
    result, gaps = [], []
    previous_timestamp = None
    missing_interface = False
    for point in points:
        if not isinstance(point, list) or not point:
            continue
        timestamp = _number(point[0])
        metadata = _point_metadata(point)
        gap = bool(metadata["gap_before"]) if "gap_before" in metadata else (
            previous_timestamp is not None and timestamp - previous_timestamp > HISTORY_GAP_SECONDS)
        previous_timestamp = timestamp
        if timestamp < lower_bound or timestamp > upper_bound:
            continue
        before = len(result)
        if metric == "network":
            interfaces = point[1] if len(point) > 1 and isinstance(point[1], dict) else {}
            if interface:
                if interface not in interfaces:
                    missing_interface = True
                    continue
                rates = interfaces[interface]
            else:
                rates = [sum(_number(rate[i]) for rate in interfaces.values()
                             if isinstance(rate, list) and len(rate) > i) for i in range(2)]
            result.append([point[0], round(_number(rates[0]), 2), round(_number(rates[1]), 2)])
        elif metric in ("cpu", "load"):
            if len(point) > 1:
                result.append([point[0], point[1]])
        elif metric in ("memory", "disk") and len(point) > 3:
            result.append([point[0], point[1], point[2], point[3]])
        if len(result) > before:
            gaps.append(gap or missing_interface)
            missing_interface = False
    original_count = len(result)
    result, gaps = _limit_history_points(result, gaps, metric)
    return {"node": node_id, "metric": metric, "range": range_name, "interface": interface,
            "start": start, "end": end, "partition": partition, "points": result, "gaps": gaps,
            "source_count": original_count, "downsampled": original_count > len(result),
            "retention_policy": {"raw_hours": 24, "five_minute_days": 7, "older_bucket_seconds": 3600}}


def _invalidate_cluster_snapshot():
    with CLUSTER_SNAPSHOT_LOCK:
        CLUSTER_SNAPSHOT_CACHE["sampled_at"] = 0.0
        CLUSTER_SNAPSHOT_CACHE["data"] = None
        CLUSTER_SNAPSHOT_CACHE["generation"] = CLUSTER_SNAPSHOT_CACHE.get("generation", 0) + 1


def _dashboard_activity():
    with ASSET_CACHE_LOCK:
        now = time.monotonic()
        if now-ASSET_ACTIVITY["last_poll"] > 30:
            ASSET_ACTIVITY["wake"] = True
        ASSET_ACTIVITY["last_poll"] = now


def _asset_sampler(stop_event):
    """Keep one outstanding request per asset; publish each completion separately."""
    due, failures, running, configurations, started = {}, {}, {}, {}, {}
    pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tinywatch-asset")
    try:
        while not stop_event.is_set():
            _worker_tick("assets", requests_used=len(running), requests_limit=8,
                         requests_overdue=sum(time.monotonic()-stamp > 30 for stamp in started.values()),
                         requests_oldest_seconds=int(max((time.monotonic()-stamp for stamp in started.values()), default=0)))
            with STORE.lock:
                assets = copy.deepcopy(STORE.data.get("assets", []))[:MAX_ASSETS]
            current = {asset["id"]: asset for asset in assets}
            for identity, asset in current.items():
                if configurations.get(identity) != asset:
                    configurations[identity] = asset
                    due[identity], failures[identity] = 0, 0
            with ASSET_CACHE_LOCK:
                active = time.monotonic()-ASSET_ACTIVITY["last_poll"] <= 30
                wake = ASSET_ACTIVITY["wake"]
                ASSET_ACTIVITY["wake"] = False
            if wake:
                for identity in current:
                    if not failures.get(identity):
                        due[identity] = min(due.get(identity, 0), time.monotonic())
            for future, asset in list(running.items()):
                if not future.done():
                    continue
                del running[future]
                started.pop(future, None)
                result = future.result()
                with STORE.lock:
                    latest = next((item for item in STORE.data.get("assets", []) if item["id"] == asset["id"]), None)
                    if latest != asset:
                        continue
                    failures[asset["id"]] = 0 if result["online"] else min(6, failures.get(asset["id"], 0)+1)
                    delay = min(300, CLUSTER_CACHE_SECONDS * 2 ** failures[asset["id"]]) if failures[asset["id"]] else (CLUSTER_CACHE_SECONDS if active else HISTORY_INTERVAL)
                    due[asset["id"]] = time.monotonic()+delay
                    result.update(received_at=int(time.time()), retry_seconds=delay,
                                  next_retry_at=int(time.time()+delay), consecutive_failures=failures[asset["id"]])
                    with ASSET_CACHE_LOCK:
                        ASSET_CACHE[asset["id"]] = {"configuration": asset, "result": result}
                _invalidate_cluster_snapshot()
            with ASSET_CACHE_LOCK:
                for identity in list(ASSET_CACHE):
                    if ASSET_CACHE[identity]["configuration"] != current.get(identity):
                        del ASSET_CACHE[identity]
            for identity in list(due):
                if identity not in current:
                    due.pop(identity, None)
                    failures.pop(identity, None)
                    configurations.pop(identity, None)
            busy = {asset["id"] for asset in running.values()}
            now = time.monotonic()
            for asset in sorted(assets, key=lambda item: due.get(item["id"], 0)):
                identity = asset["id"]
                with ASSET_CACHE_LOCK:
                    cached = ASSET_CACHE.get(identity)
                if cached is None and identity not in busy:
                    due[identity] = min(due.get(identity, now), now)
                if identity not in busy and len(running) < 8 and now >= due.get(identity, 0):
                    future = pool.submit(_remote_snapshot, asset)
                    running[future] = asset
                    started[future] = time.monotonic()
            with REMOTE_STATUS_LOCK:
                for identity in list(REMOTE_LAST_SUCCESS):
                    if identity not in current:
                        del REMOTE_LAST_SUCCESS[identity]
            stop_event.wait(.5)
    finally:
        # Do not create a replacement pool while old requests still own slots.
        pool.shutdown(wait=True, cancel_futures=True)


def collect_cluster_snapshot(force_refresh=False):
    """Combine local metrics with the latest independent asset samples."""
    with CLUSTER_SNAPSHOT_LOCK:
        cached = CLUSTER_SNAPSHOT_CACHE["data"]
        if not force_refresh and cached is not None and time.monotonic()-CLUSTER_SNAPSHOT_CACHE["sampled_at"] < CLUSTER_CACHE_SECONDS:
            return cached
    # Serve the previous sample while another request owns the refresh.
    acquired = CLUSTER_REFRESH_LOCK.acquire(blocking=force_refresh or cached is None)
    if not acquired:
        return cached
    try:
        with CLUSTER_SNAPSHOT_LOCK:
            cached = CLUSTER_SNAPSHOT_CACHE["data"]
            generation = CLUSTER_SNAPSHOT_CACHE["generation"]
            if not force_refresh and cached is not None and time.monotonic()-CLUSTER_SNAPSHOT_CACHE["sampled_at"] < CLUSTER_CACHE_SECONDS:
                return cached
        started = time.monotonic()
        metrics = collect_snapshot()
        nodes = {"local": {"id": "local", "name": socket.gethostname(), "online": True, "metrics": metrics,
                            "latency_ms": round((time.monotonic()-started)*1000, 1)}}
        with STORE.lock:
            assets = copy.deepcopy(STORE.data.get("assets", []))[:MAX_ASSETS]
        with ASSET_CACHE_LOCK:
            for asset in assets:
                cached = ASSET_CACHE.get(asset["id"])
                if cached and cached["configuration"] == asset:
                    nodes[asset["id"]] = copy.deepcopy(cached["result"])
                    node = nodes[asset["id"]]
                    age = _sample_age(node, time.time())
                    node["status"] = "connection_failed" if not node["online"] else "stale" if age is None or abs(age) > 120 else "healthy"
                else:
                    nodes[asset["id"]] = {"id": asset["id"], "name": asset["name"], "online": False,
                                          "pending": True, "status": "initializing", "metrics": None, "error": "Awaiting first sample", "last_success_at": None}
        result = {"nodes": nodes, "sampled_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        with CLUSTER_SNAPSHOT_LOCK:
            if CLUSTER_SNAPSHOT_CACHE["generation"] == generation:
                CLUSTER_SNAPSHOT_CACHE.update(data=result, sampled_at=time.monotonic())
        return result

    finally:
        CLUSTER_REFRESH_LOCK.release()


def _history_sampler(stop_event):
    """Collect cluster metrics in the background while the service is running."""
    next_sample_at = time.monotonic()
    while not stop_event.is_set():
        _worker_tick("history")
        try:
            snapshot = collect_cluster_snapshot(force_refresh=True)
            _record_history(snapshot["nodes"])
        except Exception as exc:
            sys.stderr.write("TinyWatch history sampler: %s\n" % _safe_text(exc, 180))
        next_sample_at += HISTORY_INTERVAL
        delay = next_sample_at - time.monotonic()
        if delay <= 0:
            next_sample_at = time.monotonic()
            delay = 0
        if stop_event.wait(delay):
            break


def _append_timeline(node_id, timestamp, kind, message):
    events = STORE.data.setdefault("timeline", [])
    event = {"id": uuid.uuid4().hex, "node": node_id, "timestamp": int(timestamp),
             "kind": kind, "message": _safe_text(message, 240)}
    events.append(event)
    events.sort(key=lambda item: item["timestamp"])
    del events[:-MAX_TIMELINE_EVENTS]
    return event


def _record_node_changes(node_id, node, now):
    """Compare with the last snapshot; login times record first observation."""
    metrics = node.get("metrics") or {}
    errors = metrics.get("collector_errors", {})
    info = metrics.get("info") or {}
    previous = STORE.data.setdefault("node_fingerprints", {}).get(node_id, {})
    current = dict(previous)
    fields = {"system_change": [info.get("system"), info.get("release"), info.get("version")],
              "interfaces_change": sorted(str(item.get("name")) for item in metrics.get("network", {}).get("interfaces", [])),
              "partitions_change": sorted([str(item.get("id") or _partition_id(item)), _safe_text(item.get("mount"), 256), _number(item.get("total"))]
                                           for item in metrics.get("disk", {}).get("partitions", []))}
    for kind, value in fields.items():
        collector = {"system_change": "info", "interfaces_change": "network", "partitions_change": "disk"}[kind]
        if collector in errors or (isinstance(metrics.get(collector), dict) and metrics[collector].get("supported") is False):
            continue
        if kind in previous and previous[kind] != value:
            _append_timeline(node_id, now, kind, " → ".join((str(previous[kind]), str(value))))
        current[kind] = value
    uptime = _finite_value(info.get("uptime_seconds"))
    if "info" not in errors and uptime is not None:
        if previous.get("uptime") is not None and uptime < previous["uptime"] - 120:
            _append_timeline(node_id, now, "reboot", "")
        current["uptime"] = uptime
    if "logins" not in errors:
        logins = metrics.get("logins", [])[:60]
        signatures = [hashlib.sha256(json.dumps(item, sort_keys=True).encode()).hexdigest() for item in logins]
        if "logins" in previous:
            for item, signature in zip(logins, signatures):
                if signature not in previous["logins"]:
                    _append_timeline(node_id, now, "login_observed", str(item.get("message") or item))
        current["logins"] = list(dict.fromkeys(signatures + previous.get("logins", [])))[:256]
    STORE.data["node_fingerprints"][node_id] = current


def _add_annotation(value):
    """Add or remove a bounded, local annotation; no commands are executed."""
    with STORE.lock:
        if value.get("action") == "remove":
            event_id = value.get("id")
            events = STORE.data.get("timeline", [])
            event = next((item for item in events if item["id"] == event_id and item["kind"] == "annotation"), None)
            if event is None:
                raise ValueError("Annotation not found")
            events.remove(event)
            STORE.save()
            return {"ok": True}
        node_id = value.get("node")
        valid_nodes = {"local"} | {item["id"] for item in STORE.data.get("assets", [])}
        stamp = _finite_value(value.get("timestamp"))
        now = time.time()
        message = value.get("message")
        if (not isinstance(node_id, str) or node_id not in valid_nodes or stamp is None or
                not now - _history_retention_seconds() <= stamp <= now or
                not isinstance(message, str) or not message.strip() or len(message) > 240):
            raise ValueError("Invalid asset, time or annotation (maximum 240 characters)")
        event = _append_timeline(node_id, stamp, "annotation", message.strip())
        STORE.save()
        return event


def _investigation_response(node_id, start, end, partition=""):
    """Read a retained investigation window without requesting new samples."""
    now = time.time()
    if (not isinstance(node_id, str) or len(node_id) > 100 or not math.isfinite(start) or not math.isfinite(end)
            or start >= end or end > now + 60 or start < now - _history_retention_seconds()
            or end - start > _history_retention_seconds()):
        raise ValueError("Invalid investigation time range")
    charts = {metric: _history_response(node_id, metric, "custom", start=start, end=end,
                                        partition=partition if metric == "disk" else "")
              for metric in ("cpu", "memory", "disk", "network", "load")}
    with STORE.lock:
        events = [copy.deepcopy(item) for item in STORE.data.get("timeline", [])
                  if item["node"] == node_id and start <= item["timestamp"] <= end]
        incidents = [copy.deepcopy(item) for item in STORE.data.get("incidents", [])
                     if item["node"] == node_id and item["started_at"] <= end and
                     (item.get("resolved_at") is None or item["resolved_at"] >= start)]
        observations = STORE.data.get("history", {}).get(node_id, {}).get("observations", [])
        observations = [copy.deepcopy(row) for row in observations if start <= row[0] <= end]
        if len(observations) > 240:
            step = math.ceil(len(observations) / 239)
            last = observations[-1]
            observations = observations[::step]
            if observations[-1] != last:
                observations.append(last)
        name = next((asset["name"] for asset in STORE.data.get("assets", []) if asset["id"] == node_id), node_id)
    return {"node": node_id, "name": name, "start": start, "end": min(end, now), "charts": charts,
            "events": events, "incidents": incidents, "observations": observations,
            "generated_at": int(now), "sample_interval": HISTORY_INTERVAL}


def _comparison_summary(points, metric, start, end):
    """Only raw observations support sample medians and measured coverage."""
    values, valid = [], []
    for row in points:
        if not isinstance(row, list) or len(row) < 2:
            continue
        metadata = _point_metadata(row)
        if metadata.get("resolution", 60) > 60:
            continue
        if metric == "network":
            rates = row[1] if isinstance(row[1], dict) else {}
            value = sum(sum(_number(rate) for rate in pair[:2]) for pair in rates.values() if isinstance(pair, list)) if rates else None
        else:
            value = _finite_value(row[3] if len(row) > 3 else None) if metric in ("memory", "disk") else _finite_value(row[1])
        if value is not None:
            valid.append((row[0], value, bool(metadata.get("gap_before"))))
            if start <= row[0] < end:
                values.append(value)
    valid.sort()
    covered = sum(max(0, min(end, right[0])-max(start, left[0]))
                  for left, right in zip(valid, valid[1:])
                  if 0 < right[0]-left[0] <= HISTORY_GAP_SECONDS and not right[2])
    return {"samples": len(values), "median": round(statistics.median(values), 3) if values else None,
            "peak": round(max(values), 3) if values else None,
            "coverage": round(min(1, covered/(end-start))*100, 1), "raw_only": True}


def _change_comparison(identity, center, span):
    now = time.time()
    if (not isinstance(identity, str) or center is None or span is None or not 300 <= span <= 86400
            or center > now or center-span < now-_history_retention_seconds()):
        raise ValueError("Choose a change time within retention and a window of five minutes to one day")
    with STORE.lock:
        valid = {"local"} | {item["id"] for item in STORE.data.get("assets", [])}
        if identity not in valid:
            raise ValueError("Unknown asset")
        incidents = copy.deepcopy([item for item in STORE.data.get("incidents", []) if item["node"] == identity])
        services = copy.deepcopy([item for item in STORE.data.get("services", []) if item["node"] == identity])
        buckets = {item["id"]: copy.deepcopy(STORE.data.get("service_history", {}).get(item["id"], [])) for item in services}
    histories = STORE.history_windows(identity, {"cpu", "memory", "disk", "network", "load"}, center-span-90, min(now, center+span))
    windows = {}
    for side, start, end in (("before", center-span, center), ("after", center, center+span)):
        resources = {metric: _comparison_summary(rows, metric, start, end) for metric, rows in histories.items()}
        checks = []
        for service in services:
            rows = [row for row in buckets[service["id"]] if start <= row["bucket"] and row["bucket"]+300 <= min(end, now)]
            samples = sum(row["samples"] for row in rows)
            duration = sum(row["sum_ms"] for row in rows)
            covered = sum(min(300, max(0, row["last_at"]-row["first_at"])) for row in rows)
            checks.append({"id": service["id"], "name": service["name"], "samples": samples,
                           "failures": sum(row["samples"]-row["successes"] for row in rows),
                           "mean_ms": round(duration/samples, 1) if samples else None,
                           "coverage": round(min(1, covered/span)*100, 1)})
        windows[side] = {"start": start, "end": end, "complete": end <= now, "resources": resources, "services": checks,
                         "triggered": [item["id"] for item in incidents if start <= item["triggered_at"] < min(end, now)],
                         "resolved": [item["id"] for item in incidents if item.get("resolved_at") is not None and start <= item["resolved_at"] < min(end, now)],
                         "active_at_end": [item["id"] for item in incidents if item["triggered_at"] <= min(end, now)
                                           and (item.get("resolved_at") is None or item["resolved_at"] > min(end, now))]}
    changes = {}
    for metric in histories:
        left, right = windows["before"]["resources"][metric], windows["after"]["resources"][metric]
        changes[metric] = {"median_delta": round(right["median"]-left["median"], 3) if left["median"] is not None and right["median"] is not None else None,
                           "sufficient": left["coverage"] >= 80 and right["coverage"] >= 80 and windows["after"]["complete"]}
    return {"node": identity, "center": center, "span": span, "windows": windows, "changes": changes, "generated_at": int(now)}


def _outbound_url(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("Invalid HTTP URL")
    parsed = urllib.parse.urlsplit(value.strip())
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment or any(ord(char) < 33 for char in value)):
        raise ValueError("Use an HTTP/HTTPS URL without embedded credentials or fragment")
    try:
        parsed.port
    except ValueError:
        raise ValueError("Invalid port") from None
    return parsed.geturl()


def _maintenance_for(node_id, now):
    return next((window for window in STORE.data.get("maintenance", [])
                 if window["node"] in ("*", node_id) and window["start"] <= now < window["end"]), None)


def _queue_notification(incident, kind, now):
    """Store minimal transitions, never host context or monitoring credentials."""
    if _maintenance_for(incident["node"], now):
        if kind == "resolved":
            for job in STORE.data.get("notification_queue", []):
                if job["id"] == incident["id"] + ":active" and job["status"] == "pending":
                    job["status"] = "cancelled"
        if kind == "active":
            incident["notification_suppressed"] = True
        return
    config = STORE.data.get("notifications", {})
    if not config.get("enabled") or not config.get("url"):
        return
    key = incident["id"] + ":" + kind
    jobs = STORE.data.setdefault("notification_queue", [])
    if any(job["id"] == key for job in jobs):
        incident.pop("notification_suppressed", None)
        return
    if len(jobs) >= MAX_NOTIFICATION_JOBS:
        removable = next((job for job in jobs if job["status"] != "pending"), None)
        if removable is None:
            incident["notification_dropped"] = True
            return
        jobs.remove(removable)
    jobs.append({"id": key, "status": "pending", "attempts": 0, "next_at": int(now),
                 "created_at": int(now), "payload": {"event_id": key, "event": kind, "incident_id": incident["id"],
                 "node": incident["node"], "node_name": incident["node_name"], "metric": incident["metric"],
                 "name": incident["rule_name"], "value": incident["last_value"], "threshold": incident["threshold"],
                 "triggered_at": incident["triggered_at"], "resolved_at": incident.get("resolved_at"),
                 "reason": incident.get("resolution_reason")}})
    incident.pop("notification_suppressed", None)


def _service_response():
    with STORE.lock:
        now = time.time()
        return copy.deepcopy({"revision": STORE.data.get("service_revision", 0), "heartbeats": STORE.data.get("heartbeats", []), "runs": STORE.data.get("job_runs", {}), "services": STORE.data.get("services", []), "states": STORE.data.get("service_states", {}),
                "history": {key: [bucket for bucket in rows if bucket["last_at"] >= now-86400][-288:]
                            for key, rows in STORE.data.get("service_history", {}).items()}, "maintenance": STORE.data.get("maintenance", []),
                "notifications": STORE.data.get("notifications", {}),
                "deliveries": [{key: job.get(key) for key in ("id", "status", "attempts", "created_at", "next_at", "error")}
                               for job in STORE.data.get("notification_queue", [])[-30:][::-1]],
                "active_maintenance": [window["id"] for window in STORE.data.get("maintenance", []) if window["start"] <= now < window["end"]]})


class ConfigurationConflict(ValueError):
    """A stale editor must reload rather than overwrite a newer configuration."""


def _save_services(value):
    with STORE.lock:
        revision = STORE.data.get("service_revision", 0)
        if type(value.get("revision")) is not int or value["revision"] != revision:
            raise ConfigurationConflict("Configuration changed. Refresh and retry.")
        previous = STORE.data
        STORE.data = _configuration_candidate(previous)
        try:
            result = _apply_services(value)
        except Exception:
            STORE.data = previous
            raise
        return result


def _apply_services(value):
    with STORE.lock:
        valid_nodes = {"local"} | {asset["id"] for asset in STORE.data.get("assets", [])}
        if value.get("action") == "notifications":
            enabled = value.get("enabled")
            if not isinstance(enabled, bool):
                raise ValueError("Invalid notification flag")
            url = _outbound_url(value.get("url")) if value.get("url") else ""
            if enabled and not url:
                raise ValueError("Webhook URL is required")
            STORE.data["notifications"] = {"enabled": enabled, "url": url}
        elif value.get("action") == "maintenance":
            windows = value.get("windows")
            if not isinstance(windows, list) or len(windows) > 32:
                raise ValueError("At most 32 maintenance windows")
            clean, ids = [], set()
            for window in windows:
                if not isinstance(window, dict):
                    raise ValueError("Invalid maintenance window")
                identity, node = window.get("id"), window.get("node")
                start, end = _finite_value(window.get("start")), _finite_value(window.get("end"))
                label = window.get("name", "")
                if (not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", identity)
                        or identity in ids or not isinstance(node, str) or node not in valid_nodes | {"*"}
                        or start is None or end is None or start >= end or end-start > 30*86400
                        or not isinstance(label, str) or len(label) > 80):
                    raise ValueError("Invalid maintenance identity, asset or date range")
                ids.add(identity)
                clean.append({"id": identity, "node": node, "start": int(start), "end": int(end), "name": label.strip()})
            STORE.data["maintenance"] = clean
        elif value.get("action") == "heartbeats":
            rows = value.get("heartbeats")
            if not isinstance(rows, list) or len(rows) > 24:
                raise ValueError("At most 24 heartbeat jobs")
            old = {job["id"]: job for job in STORE.data.get("heartbeats", [])}
            service_ids = {item["id"] for item in STORE.data.get("services", [])}
            clean, identities = [], set()
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError("Invalid heartbeat")
                identity, node, name = row.get("id"), row.get("node"), row.get("name")
                interval, grace = row.get("interval"), row.get("grace")
                max_runtime = row.get("max_runtime", 3600)
                if (not isinstance(identity, str) or not re.fullmatch(r"job-[A-Za-z0-9_-]{1,90}", identity)
                        or identity in identities or identity in service_ids or not isinstance(node, str) or node not in valid_nodes
                        or not isinstance(name, str) or not name.strip() or len(name) > 80
                        or type(interval) is not int or not 60 <= interval <= 30*86400
                        or type(grace) is not int or not 0 <= grace <= 7*86400
                        or type(max_runtime) is not int or not 60 <= max_runtime <= 7*86400):
                    raise ValueError("Invalid heartbeat identity, interval or grace")
                identities.add(identity)
                prior = old.get(identity, {})
                clean.append({"id": identity, "node": node, "name": name.strip(), "interval": interval,
                              "grace": grace, "max_runtime": max_runtime, "token": prior.get("token") or secrets.token_urlsafe(24),
                              "created_at": prior.get("created_at", int(time.time())),
                              "last_success_at": prior.get("last_success_at"), "last_duration_ms": prior.get("last_duration_ms")})
            removed = set(old)-identities
            moved = {job["id"] for job in clean if job["id"] in old and old[job["id"]]["node"] != job["node"]}
            for identity in moved:
                STORE.data.get("job_runs", {}).pop(identity, None)
                STORE.data.get("service_states", {}).pop(identity, None)
            for incident in STORE.data.get("incidents", []):
                if incident.get("status") == "active" and incident.get("service_id") in removed | moved:
                    _resolve_incident(incident, time.time(), "rule_changed")
            for identity in removed:
                STORE.data.get("job_runs", {}).pop(identity, None)
                STORE.data.get("service_states", {}).pop(identity, None)
                STORE.data.get("service_history", {}).pop(identity, None)
                STORE.mark_history_dirty()
            STORE.data["heartbeats"] = clean
        elif value.get("action") == "services":
            rows = value.get("services")
            if not isinstance(rows, list) or len(rows) > MAX_SERVICES:
                raise ValueError("At most 24 service monitors")
            clean, ids = [], set()
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError("Invalid service")
                identity, node, protocol = row.get("id"), row.get("node"), row.get("protocol")
                name, target, match = row.get("name"), row.get("target"), row.get("match", "")
                interval, timeout = _finite_value(row.get("interval")), _finite_value(row.get("timeout"))
                failures = _finite_value(row.get("failures"))
                if (not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", identity) or identity in ids or identity.startswith("job-")
                        or not isinstance(node, str) or node not in valid_nodes or protocol not in ("http", "tcp", "tls")
                        or not isinstance(name, str) or not name.strip() or len(name) > 80
                        or interval is None or interval != int(interval) or not 30 <= interval <= 3600
                        or timeout is None or not 1 <= timeout <= 10 or failures is None or failures != int(failures) or not 1 <= failures <= 10
                        or not isinstance(match, str) or len(match) > 128 or not isinstance(row.get("enabled", True), bool)):
                    raise ValueError("Invalid service identity or limits")
                cert_days = row.get("cert_days", 30)
                if type(cert_days) is not int or cert_days not in (7, 14, 30):
                    raise ValueError("Certificate warning must be 7, 14 or 30 days")
                status = row.get("status", 200)
                if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status <= 599:
                    raise ValueError("Invalid expected HTTP status")
                port = row.get("port", 443)
                if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
                    raise ValueError("Invalid TCP port")
                if protocol == "http":
                    target = _outbound_url(target)
                elif not isinstance(target, str) or len(target) > 253 or not re.fullmatch(r"[A-Za-z0-9_.:\-]+", target):
                    raise ValueError("Use a TCP hostname or IP without a URL or port")
                ids.add(identity)
                clean.append({"id": identity, "node": node, "name": name.strip(), "protocol": protocol,
                              "target": target, "port": port, "match": match, "status": status,
                              "interval": int(interval), "timeout": timeout, "failures": int(failures),
                              "cert_days": cert_days, "enabled": row.get("enabled", True)})
            old = {item["id"]: item for item in STORE.data.get("services", [])}
            current = {item["id"]: item for item in clean}
            identity_fields = ("node", "protocol", "target", "port", "match", "status")
            changed = {key for key in old if key not in current or any(old[key].get(field) != current[key].get(field) for field in identity_fields)}
            for incident in STORE.data.get("incidents", []):
                if incident.get("status") == "active" and incident.get("service_id") in changed:
                    _resolve_incident(incident, time.time(), "rule_changed")
            for key in changed:
                STORE.data.get("service_states", {}).pop(key, None)
                STORE.data.get("service_history", {}).pop(key, None)
                STORE.mark_history_dirty()
            for identity, service in current.items():
                if identity not in old or identity in changed:
                    continue
                state = STORE.data.get("service_states", {}).get(identity)
                if state and any(old[identity].get(field) != service.get(field) for field in ("enabled", "failures", "interval", "timeout", "cert_days")):
                    state["failed_count"] = 0
                    state.pop("failed_since", None)
                for incident in STORE.data.get("incidents", []):
                    if incident.get("service_id") == identity and incident.get("status") == "active":
                        incident["rule_name"] = service["name"]
                        if not service["enabled"]:
                            _resolve_incident(incident, time.time(), "monitor_disabled")
                            if state:
                                state.pop("active_id", None)
            STORE.data["services"] = clean
        else:
            raise ValueError("Invalid service configuration action")
        STORE.data["service_revision"] = STORE.data.get("service_revision", 0) + 1
        STORE.save()
    return _service_response()


def _probe_service(service):
    started = time.monotonic()
    try:
        return _bounded_network_probe("service", service, service["timeout"]+2)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"sampled_at": int(time.time()), "ok": False, "latency_ms": round((time.monotonic()-started)*1000, 1),
                "status_code": None, "error": "probe_timeout", "certificate_expires_at": None,
                "certificate_days_remaining": None}


def _probe_service_direct(service):
    """Probe from the console host; TLS uses hostname and chain verification."""
    started = time.monotonic()
    code, error, ok, certificate = None, "", False, {}
    try:
        if service["protocol"] in ("tcp", "tls"):
            with socket.create_connection((service["target"], service["port"]), timeout=service["timeout"]) as connection:
                if service["protocol"] == "tls":
                    context = ssl.create_default_context()
                    with context.wrap_socket(connection, server_hostname=service["target"]) as secured:
                        peer = secured.getpeercert()
                        expires = ssl.cert_time_to_seconds(peer["notAfter"])
                        remaining = (expires-time.time())/86400
                        certificate = {"certificate_expires_at": int(expires), "certificate_days_remaining": round(remaining, 2)}
                        ok = remaining > service.get("cert_days", 30)
                        if not ok:
                            error = "certificate_expiring"
                else:
                    ok = True
        else:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirectHandler())
            request = urllib.request.Request(service["target"], headers={"User-Agent": APP_NAME + "/" + APP_VERSION})
            try:
                response = opener.open(request, timeout=service["timeout"])
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                code = response.code
                body = response.read(65536) if service["match"] else b""
            ok = code == service["status"] and (not service["match"] or service["match"] in body.decode("utf-8", "replace"))
            if not ok:
                error = "unexpected_status" if code != service["status"] else "content_mismatch"
    except ssl.SSLCertVerificationError:
        error = "certificate_invalid"
    except ssl.SSLError:
        error = "tls_failed"
    except socket.gaierror:
        error = "dns_failed"
    except (TimeoutError, socket.timeout):
        error = "probe_timeout"
    except Exception:
        error = "connection_failed"
    return {"sampled_at": int(time.time()), "ok": ok, "latency_ms": round((time.monotonic()-started)*1000, 1),
            "status_code": code, "error": error, "certificate_expires_at": certificate.get("certificate_expires_at"),
            "certificate_days_remaining": certificate.get("certificate_days_remaining")}


def _record_probe(service, result):
    now, identity = result["sampled_at"], service["id"]
    states = STORE.data.setdefault("service_states", {})
    state = states.setdefault(identity, {})
    # An unobserved gap resets consecutive failures instead of extending evidence.
    if now-state.get("sampled_at", now) > service["interval"]*2+service["timeout"]:
        state["failed_count"] = 0
        state.pop("failed_since", None)
    if result["ok"]:
        state.pop("failed_since", None)
    else:
        state.setdefault("failed_since", now)
    state["failed_count"] = 0 if result["ok"] else min(1000000, state.get("failed_count", 0)+1)
    state.update(result)
    incident = next((item for item in STORE.data.get("incidents", []) if item.get("id") == state.get("active_id") and item.get("status") == "active"), None)
    if incident:
        incident["last_value"] = 0 if result["ok"] else 1
        incident["last_observed_at"] = now
        if result["ok"]:
            _resolve_incident(incident, now, "recovered")
            state.pop("active_id", None)
    elif state["failed_count"] >= service["failures"]:
        incident = {"id": uuid.uuid4().hex, "service_id": identity, "rule_id": "service-"+identity,
                    "rule_name": service["name"], "node": service["node"],
                    "node_name": next((item["name"] for item in STORE.data.get("assets", []) if item["id"] == service["node"]), socket.gethostname() if service["node"] == "local" else service["node"]),
                    "metric": "service", "mode": "threshold", "status": "active", "started_at": state.get("failed_since", now),
                    "triggered_at": now, "resolved_at": None, "acknowledged_at": None,
                    "threshold": 0, "recovery": 0, "duration": now-state.get("failed_since", now), "value": 1, "last_value": 1, "peak": 1,
                    "last_observed_at": now, "baseline": None, "context": {"probe_error": result["error"]}}
        STORE.data.setdefault("incidents", []).append(incident)
        _start_flight_record(incident)
        state["active_id"] = incident["id"]
        _queue_notification(incident, "active", now)
    buckets = STORE.data.setdefault("service_history", {}).setdefault(identity, [])
    bucket_time = now//300*300
    index = bisect.bisect_left(buckets, bucket_time, key=lambda item: item["bucket"])
    if index == len(buckets) or buckets[index]["bucket"] != bucket_time:
        buckets.insert(index, {"bucket": bucket_time, "first_at": now, "last_at": now, "samples": 0, "successes": 0,
                               "sum_ms": 0, "min_ms": result["latency_ms"], "max_ms": result["latency_ms"]})
    bucket = buckets[index]
    bucket.update(first_at=min(now, bucket["first_at"]), last_at=max(now, bucket["last_at"]),
                  samples=bucket["samples"]+1, successes=bucket["successes"]+int(result["ok"]),
                  sum_ms=bucket["sum_ms"]+result["latency_ms"], min_ms=min(bucket["min_ms"], result["latency_ms"]),
                  max_ms=max(bucket["max_ms"], result["latency_ms"]))
    _mark_changed_rows(STORE.data, buckets[:-2048], service=True)
    STORE.mark_history_dirty(now)
    del buckets[:-2048]


def _heartbeat_service(job):
    return dict(job, failures=1, timeout=0)


def _heartbeat_rollback(identities):
    previous = STORE.data
    candidate = {key: (value if key in ("history", "service_history") else copy.deepcopy(value))
                 for key, value in previous.items()}
    candidate["service_history"] = dict(previous.get("service_history", {}))
    for identity in identities:
        if identity in candidate["service_history"]:
            candidate["service_history"][identity] = copy.deepcopy(candidate["service_history"][identity])
    STORE.data = candidate
    return previous


def _prune_job_runs(now):
    cutoff = now-_history_retention_seconds()
    runs = STORE.data.setdefault("job_runs", {})
    valid = {job["id"] for job in STORE.data.get("heartbeats", [])}
    for identity in list(runs):
        if identity not in valid:
            del runs[identity]
            continue
        rows = [row for row in runs[identity] if row["status"] == "running" or row.get("finished_at", row.get("started_at", 0)) >= cutoff]
        active = [row for row in rows if row["status"] == "running"]
        completed = [row for row in rows if row["status"] != "running"]
        runs[identity] = sorted(completed[-(50-len(active)):]+active, key=lambda row: row.get("started_at") or row.get("finished_at", 0))


def _check_heartbeats():
    """Running jobs have a bounded runtime; idle jobs retain the success deadline."""
    now = int(time.time())
    with STORE.lock:
        plans = []
        for job in STORE.data.get("heartbeats", []):
            runs = STORE.data.get("job_runs", {}).get(job["id"], [])
            active = [row for row in runs if row["status"] == "running"]
            expired = [row["id"] for row in active if now > row["started_at"]+job.get("max_runtime", 3600)]
            deadline = (job.get("last_success_at") or job["created_at"])+job["interval"]+job["grace"]
            missing = not active and now > deadline and not STORE.data.get("service_states", {}).get(job["id"], {}).get("active_id")
            if expired or missing:
                plans.append((job["id"], expired))
        if not plans:
            return
        previous = _heartbeat_rollback([identity for identity, _ in plans])
        try:
            for identity, expired in plans:
                job = next(item for item in STORE.data["heartbeats"] if item["id"] == identity)
                for row in STORE.data.get("job_runs", {}).get(identity, []):
                    if row["id"] in expired:
                        row.update(status="timeout", finished_at=now, timed_out_at=now,
                                   duration_ms=(now-row["started_at"])*1000)
                _record_probe(_heartbeat_service(job), {"sampled_at": now, "ok": False, "latency_ms": 0,
                              "status_code": None, "error": "task_timeout" if expired else "heartbeat_overdue"})
            _prune_job_runs(now)
            STORE.save()
        except Exception:
            STORE.data = previous
            raise


def _receive_heartbeat(value, token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", token):
        return False
    with STORE.lock:
        job = next((item for item in STORE.data.get("heartbeats", []) if secrets.compare_digest(item["token"], token)), None)
        if job is None:
            return False
        event, identity = value.get("event", "success"), value.get("run_id")
        message, duration = value.get("message", ""), value.get("duration_ms")
        if event not in ("start", "success", "fail"):
            raise ValueError("Use event start, success or fail")
        if identity is not None and (not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,100}", identity)):
            raise ValueError("Invalid run_id")
        if event != "success" and identity is None:
            raise ValueError("Start and failure reports require run_id")
        if not isinstance(message, str) or len(message) > 240:
            raise ValueError("Result message must be at most 240 characters")
        if duration is not None and (isinstance(duration, bool) or not isinstance(duration, (int, float))
                or not math.isfinite(duration) or not 0 <= duration <= 30*86400*1000):
            raise ValueError("Invalid task duration")
        rows = STORE.data.get("job_runs", {}).get(job["id"], [])
        run = next((row for row in rows if row["id"] == identity), None) if identity else None
        status = {"start": "running", "success": "success", "fail": "failed"}[event]
        if run and run["status"] == status:
            return True
        if run and run["status"] not in ("running", "timeout"):
            raise ValueError("Run already completed with a different result")
        if run and event == "start":
            raise ValueError("A completed run cannot restart; use a new run_id")
        if event == "start" and sum(row["status"] == "running" for row in rows) >= 4:
            raise ValueError("At most four simultaneous runs per task")
        previous = _heartbeat_rollback([job["id"]])
        job = next(item for item in STORE.data["heartbeats"] if item["id"] == job["id"])
        try:
            now = int(time.time())
            rows = STORE.data.setdefault("job_runs", {}).setdefault(job["id"], [])
            run = next((row for row in rows if row["id"] == identity), None) if identity else None
            if run is None:
                run = {"id": identity or "legacy-"+uuid.uuid4().hex, "started_at": now if event == "start" else None,
                       "overlap": event == "start" and any(row["status"] == "running" for row in rows)}
                rows.append(run)
            run.update(status=status, message=_safe_text(message, 240))
            if event != "start":
                duration = duration if duration is not None else max(0, (now-run["started_at"])*1000) if run.get("started_at") else 0
                run.update(finished_at=now, duration_ms=duration)
                if event == "success":
                    job.update(last_success_at=now, last_duration_ms=duration)
                _record_probe(_heartbeat_service(job), {"sampled_at": now, "ok": event == "success", "latency_ms": duration,
                              "status_code": None, "error": "" if event == "success" else "task_failed"})
            _prune_job_runs(now)
            STORE.save()
        except Exception:
            STORE.data = previous
            raise
        return True


def _service_sampler(stop_event):
    """At most four outstanding probes; missed ticks are skipped, never queued."""
    due, running, configurations, started = {}, {}, {}, {}
    dirty, last_save = False, time.monotonic()
    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="tinywatch-probe")
    try:
        while not stop_event.is_set():
            _worker_tick("services", probe_slots_used=len(running), probe_slots_limit=4,
                         probes_overdue=sum(time.monotonic()-started[future] > service["timeout"]+30
                                            for future, service in running.items()),
                         oldest_probe_seconds=int(max((time.monotonic()-stamp for stamp in started.values()), default=0)))
            try:
                _check_heartbeats()
            except OSError:
                sys.stderr.write("TinyWatch heartbeat worker: database write failed\n")
            with STORE.lock:
                services = copy.deepcopy(STORE.data.get("services", []))
            current = {service["id"]: service for service in services}
            completed = [(future, service) for future, service in running.items() if future.done()]
            if completed:
                with STORE.lock:
                    current = {item["id"]: item for item in STORE.data.get("services", [])}
                    changed, urgent = False, False
                    for future, service in completed:
                        del running[future]
                        started.pop(future, None)
                        if current.get(service["id"]) == service:
                            before = STORE.data.get("service_states", {}).get(service["id"], {}).get("active_id")
                            _record_probe(service, future.result())
                            after = STORE.data.get("service_states", {}).get(service["id"], {}).get("active_id")
                            urgent = urgent or before != after
                            changed = True
                    if changed:
                        if time.time()-STORE.last_prune_at >= 60:
                            _prune_history_database(STORE.data, time.time()-_history_retention_seconds())
                            STORE.last_prune_at = time.time()
                        dirty = True
                        if urgent:
                            try:
                                STORE.save()
                                dirty = False
                            except OSError:
                                sys.stderr.write("TinyWatch service worker: database write failed\n")
                            last_save = time.monotonic()
            if dirty and time.monotonic()-last_save >= 10:
                with STORE.lock:
                    try:
                        STORE.save()
                        dirty = False
                    except OSError:
                        sys.stderr.write("TinyWatch service worker: database write failed\n")
                last_save = time.monotonic()
            busy = {service["id"] for service in running.values()}
            for identity in list(due):
                if identity not in current:
                    del due[identity]
                    configurations.pop(identity, None)
            now = time.monotonic()
            for service in services:
                if configurations.get(service["id"]) != service:
                    configurations[service["id"]] = service
                    due[service["id"]] = now+secrets.randbelow(5)
            # Oldest due monitor first, so slow targets cannot starve later rows.
            for service in sorted(services, key=lambda item: due[item["id"]]):
                identity = service["id"]
                if not service["enabled"] or identity in busy or len(running) >= 4:
                    continue
                due.setdefault(identity, now+secrets.randbelow(5))
                if now >= due[identity]:
                    with STORE.lock:
                        latest = next((item for item in STORE.data.get("services", []) if item["id"] == identity), None)
                        if latest != service:
                            continue
                    future = pool.submit(_probe_service, service)
                    running[future] = service
                    started[future] = time.monotonic()
                    due[identity] = now+service["interval"]
            stop_event.wait(1)
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        if dirty:
            with STORE.lock:
                try:
                    STORE.save()
                except OSError:
                    sys.stderr.write("TinyWatch service worker: final database write failed\n")


def _notification_sampler(stop_event):
    """Deliver outside store/collector locks with finite retries and expiry."""
    while not stop_event.wait(2):
        _worker_tick("notifications")
        try:
            with STORE.lock:
                now = time.time()
                config = copy.deepcopy(STORE.data.get("notifications", {}))
                if not config.get("enabled") or not config.get("url"):
                    continue
                resumed = False
                for incident in STORE.data.get("incidents", []):
                    if incident.get("status") == "active" and incident.get("notification_suppressed") and not _maintenance_for(incident["node"], now):
                        _queue_notification(incident, "active", now)
                        resumed = True
                        if incident.get("notification_dropped"):
                            incident.pop("notification_suppressed", None)
                if resumed:
                    STORE.save()
                config = copy.deepcopy(STORE.data.get("notifications", {}))
                if not config.get("enabled") or not config.get("url"):
                    continue
                jobs = STORE.data.get("notification_queue", [])
                job = next((item for item in jobs if item["status"] == "pending" and item["next_at"] <= now
                            and not _maintenance_for(item["payload"]["node"], now)), None)
                if job is None:
                    continue
                if now-job["created_at"] > 86400:
                    job.update(status="expired", error="delivery_expired")
                    STORE.save()
                    continue
                snapshot = copy.deepcopy(job)
            ok = False
            try:
                request = urllib.request.Request(config["url"], data=json.dumps(snapshot["payload"]).encode(),
                                                 headers={"Content-Type": "application/json"}, method="POST")
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _RejectRedirectHandler())
                with opener.open(request, timeout=5) as response:
                    ok = 200 <= response.status < 300
            except Exception:
                pass
            with STORE.lock:
                job = next((item for item in STORE.data.get("notification_queue", []) if item["id"] == snapshot["id"]), None)
                if job is not None:
                    job["attempts"] += 1
                    job["status"] = "delivered" if ok else "failed" if job["attempts"] >= 5 else "pending"
                    job["error"] = "" if ok else "delivery_failed"
                    job["next_at"] = int(time.time()+min(900, 30*2**job["attempts"]))
                    STORE.save()
        except Exception:
            sys.stderr.write("TinyWatch notification worker: persistence or delivery failure\n")


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
.fleet-health{margin:0 0 18px;padding:13px 15px;border:1px solid var(--line);border-radius:14px;background:var(--surface)}
.fleet-label{font-size:11px;color:var(--muted);margin-bottom:9px}.fleet-nodes{display:flex;flex-wrap:wrap;gap:7px}
.fleet-node{display:flex;align-items:center;gap:7px;max-width:100%;padding:7px 10px;border:1px solid var(--line);border-radius:9px;background:var(--surface2);color:var(--text);font-size:11px}
.fleet-node span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.fleet-node small{color:var(--muted)}
.health-dot{flex:none;width:6px;height:6px;border-radius:50%;background:var(--accent)}.partial .health-dot,.stale .health-dot{background:var(--warn)}.offline .health-dot{background:var(--bad)}
.button.has-alerts{color:var(--bad);border-color:var(--bad)}.feature-tabs,.feature-toolbar,.rule-actions,.incident-actions{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:12px 0}
.feature-tabs{border-bottom:1px solid var(--line);padding-bottom:12px}.feature-toolbar select{min-height:35px;max-width:100%}.feature-tabs button{font-size:12px}
.incident-list,.rule-list,.diagnostic-list{display:grid;gap:12px}.incident,.rule-card,.diagnostic-card{border:1px solid var(--line);border-radius:12px;padding:15px;background:var(--surface2);min-width:0}
.incident.active{border-left:3px solid var(--bad)}.incident.resolved{border-left:3px solid var(--accent)}.feature-card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.feature-card-head strong{overflow-wrap:anywhere}
.health-status{display:inline-block;flex:none;border-radius:6px;padding:3px 7px;font-size:10px;background:var(--surface3);color:var(--muted)}.health-status.healthy{color:var(--accent)}.health-status.offline{color:var(--bad)}.health-status.stale,.health-status.partial{color:var(--warn)}
.feature-facts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:11px 18px;margin:14px 0}.feature-facts div{min-width:0}.feature-facts dt{color:var(--muted);font-size:10px}.feature-facts dd{margin:3px 0 0;font-size:12px;overflow-wrap:anywhere}.feature-facts small{display:block;font-size:10px;color:var(--muted)}
.incident details{border-top:1px solid var(--line);padding-top:10px}.incident summary{cursor:pointer;font-size:12px;color:var(--accent2)}.context-log,.diagnostic-issues{font-size:11px;overflow-wrap:anywhere}.diagnostic-issues{padding-left:18px}.diagnostic-issues li{margin:8px 0}.diagnostic-issues p{margin:3px 0;color:var(--muted)}.table-scroll{overflow:auto}.baseline-evidence{font-size:12px;color:var(--accent2)}
.rule-editor{padding:15px;border:1px solid var(--accent2);border-radius:12px;margin-bottom:16px}.checkbox-label{display:flex!important;align-items:center;gap:8px}.checkbox-label input{width:auto!important}.rule-actions,.incident-actions{margin-bottom:0}.panel-actions{flex-wrap:wrap}.modal .helper{overflow-wrap:anywhere}
@media(max-width:680px){.feature-facts{gap:10px}.feature-toolbar{align-items:stretch}.feature-toolbar select{flex:1;min-width:0}.fleet-node{flex-wrap:wrap}.fleet-node small{font-size:9px}.incident,.rule-card,.diagnostic-card{padding:12px}.feature-card-head{gap:8px}.health-status{max-width:45%;text-align:center}.feature-tabs button{flex:1;font-size:11px}.rule-editor .form-grid{grid-template-columns:1fr}.feature-card-head .metric-sub{overflow-wrap:anywhere}}
.replay-charts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.replay-chart{border:1px solid var(--line);border-radius:12px;padding:12px;min-width:0}.replay-chart h4{margin:0}.replay-chart .mini-chart{height:180px}.replay-events{display:grid;gap:8px;margin:14px 0;max-height:260px;overflow:auto}.replay-event{padding:10px;background:var(--surface2);border-left:3px solid var(--accent2);border-radius:8px;overflow-wrap:anywhere}.replay-event.annotation{border-left-color:var(--accent)}.replay-readout{font-variant-numeric:tabular-nums}.replay-toolbar{display:flex;flex-wrap:wrap;gap:7px;margin:12px 0}.replay-context{overflow-wrap:anywhere}.replay-marker{stroke:var(--warn);stroke-width:1;stroke-dasharray:2 3;pointer-events:none}.replay-event button{float:right}.replay-window-controls{display:flex;gap:6px;flex-wrap:wrap}@media(max-width:680px){.replay-charts{grid-template-columns:1fr}.replay-toolbar .button{flex:1}.modal.wide-modal{max-height:90vh}.replay-chart .mini-chart{height:165px}}
.service-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.service-grid .helper{overflow-wrap:anywhere}.service-grid .mini-chart{height:148px}@media(max-width:680px){.service-grid{grid-template-columns:1fr}.panel-actions{flex-wrap:wrap}}
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
  ['首次设置代码','One-time setup code','初回セットアップコード','Code de configuration initiale','Одноразовый код первоначальной настройки','Einmaliger Einrichtungscode'],
  ['请输入启动 TinyWatch 的终端中显示的一次性代码。','Enter the one-time code shown in the terminal running TinyWatch.','TinyWatch を起動したターミナルに表示されるワンタイムコードを入力してください。','Saisissez le code à usage unique affiché dans le terminal où TinyWatch est lancé.','Введите одноразовый код, показанный в терминале TinyWatch.','Geben Sie den Einmalcode aus dem Terminal ein, in dem TinyWatch läuft.'],
  ['输入一次性设置代码','Enter one-time setup code','ワンタイム設定コードを入力','Saisissez le code de configuration','Введите одноразовый код настройки','Einmaligen Einrichtungscode eingeben'],
  ['首次设置代码无效或已过期','The setup code is invalid or has expired.','セットアップコードが無効か、有効期限が切れています。','Le code de configuration est invalide ou expiré.','Код настройки недействителен или срок его действия истёк.','Der Einrichtungscode ist ungültig oder abgelaufen.'],
  ['最后成功采样','Last successful sample','最後に成功したサンプル','Dernier échantillon réussi','Последний успешный сбор','Letzte erfolgreiche Messung'],
  ['指标暂不可用','Metric unavailable','メトリックを利用できません','Mesure indisponible','Метрика недоступна','Messwert nicht verfügbar'],
  ['离线','Offline','オフライン','Hors ligne','Не в сети','Offline'],
  ['尚未采样','Not sampled yet','まだサンプリングされていません','Pas encore mesuré','Ещё не собирались данные','Noch nicht erfasst']
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
    const setupToken = document.getElementById('setup-token');
    const savedPassword = password ? password.value : '';
    const savedPassword2 = password2 ? password2.value : '';
    const savedSetupToken = setupToken ? setupToken.value : '';
    state.language = LANGUAGE_NAMES[select.value] ? select.value : 'en';
    try { localStorage.setItem('tinywatch.language', state.language); } catch (error) { /* private mode */ }
    document.documentElement.lang = state.language;
    if (state.authenticated) render();
    else {
      authScreen(state.setup);
      const nextPassword = document.getElementById('password');
      const nextPassword2 = document.getElementById('password2');
      const nextSetupToken = document.getElementById('setup-token');
      if (nextPassword) nextPassword.value = savedPassword;
      if (nextPassword2) nextPassword2.value = savedPassword2;
      if (nextSetupToken) nextSetupToken.value = savedSetupToken;
    }
  };
}

const state={authenticated:false,setup:false,config:null,data:null,history:{},historical:{},historyPending:{},historyRequests:{},serviceTab:"monitors",serviceData:null,serviceRequest:0,serviceLoading:false,serviceFetchedAt:0,serviceEditing:false,replay:null,replayRequest:0,replayController:null,refreshing:false,pollGeneration:0,historyRanges:{},historyCustom:{},chartData:{},chartSequence:0,timer:null,freshnessTimer:null,lastRefreshAt:0,refreshFailed:false,dragged:null,modal:null,modalKind:'',alertData:null,alertTab:'incidents',alertStatus:'all',alertNode:'*',alertRequest:0,alertFetchedAt:0,alertLoading:false,view:'overview',language:LANGUAGE_NAMES[readPreference('tinywatch.language','en')]?readPreference('tinywatch.language','en'):'en'};
document.documentElement.lang=state.language;
const metrics={cpu:['处理器','◉'],memory:['内存','▤'],network:['网络流量','↕'],disk:['磁盘','▣'],load:['系统负载','⌁'],processes:['进程','▥'],logins:['登录事件','⌑'],dns:['DNS 缓存','⌘'],info:['主机信息','◈']};
const fmtBytes=n=>{n=Number(n)||0;const u=['B','KB','MB','GB','TB'];let i=0;while(n>=1024&&i<u.length-1){n/=1024;i++}return new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{minimumFractionDigits:i?1:0,maximumFractionDigits:i?1:0}).format(i===0?Math.round(n):n)+' '+u[i]};
const pct=n=>Math.max(0,Math.min(100,Number(n)||0));
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,method='GET',body,signal){const r=await fetch(path,{signal,method,headers:body?{'Content-Type':'application/json'}:{},body:body?JSON.stringify(body):undefined,credentials:'same-origin'});let j={};try{j=await r.json()}catch(e){}if(!r.ok){const error=new Error(j.error||('HTTP '+r.status));error.status=r.status;throw error}return j}
function toast(text){const el=document.getElementById('toast');el.textContent=tr(text);el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2200)}
function setTheme(theme){document.documentElement.dataset.theme=theme||'dark'}
function authScreen(isSetup){
  state.serviceRequest++;state.serviceEditing=false;
  state.pollGeneration++;clearTimeout(state.timer);clearInterval(state.freshnessTimer);
  state.replayRequest++;state.replayController?.abort();for(const request of Object.values(state.historyRequests))request.controller.abort();
  state.setup=isSetup;
  app.innerHTML='<div class="auth-wrap"><section class="auth-card"><div class="auth-tools">'+languageSelector()+'</div><div class="brand" style="padding:0"><div class="brand-mark">◈</div><div><strong>TinyWatch</strong><small>INFRASTRUCTURE CONSOLE</small></div></div><h1>'+(isSetup?'建立管理员密码':'欢迎回来')+'</h1><p>'+(isSetup?'首次使用，请设置用于此控制台的密码。':'登录后查看主机与网络资产指标。')+'</p><form id="auth-form">'+(isSetup?'<div class="field"><label>首次设置代码</label><input id="setup-token" type="password" autocomplete="off" required placeholder="输入一次性设置代码"><div class="helper">请使用启动 TinyWatch 的终端中显示的一次性代码。</div></div>':'')+'<div class="field"><label>管理员密码</label><input id="password" type="password" autocomplete="'+(isSetup?'new-password':'current-password')+'" required minlength="'+(isSetup?'10':'1')+'" autofocus placeholder="'+(isSetup?'至少 10 个字符':'输入密码')+'"></div>'+(isSetup?'<div class="field"><label>确认密码</label><input id="password2" type="password" autocomplete="new-password" required minlength="10" placeholder="再次输入密码"></div>':'')+'<div id="auth-error" class="error-message"></div><button class="button primary" type="submit">'+(isSetup?'设置密码并继续':'登录控制台')+'</button></form><div class="login-note">密码使用 PBKDF2-SHA256 加盐存储在本机 JSON 数据库中。</div></section></div>';
  document.documentElement.lang=state.language;
  localizeDOM(app);
  bindLanguageSelector();
  document.getElementById('auth-form').onsubmit=async e=>{e.preventDefault();const p=document.getElementById('password').value;try{if(isSetup&&p!==document.getElementById('password2').value)throw new Error('两次输入的密码不一致');const payload={password:p};if(isSetup)payload.setup_token=document.getElementById('setup-token').value;await api(isSetup?'/api/setup':'/api/login','POST',payload);await enterApp()}catch(err){document.getElementById('auth-error').textContent=tr(err.message)}};
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
  const generation=++state.pollGeneration;
  clearTimeout(state.timer);
  clearInterval(state.freshnessTimer);
  state.freshnessTimer=setInterval(updateFreshnessIndicator,1000);
  const poll=async()=>{await refresh();if(state.authenticated&&generation===state.pollGeneration)state.timer=setTimeout(poll,document.hidden?30000:2500)};
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
  if(!state.authenticated||state.refreshing)return;
  state.refreshing=true;
  try{
    const data=await api('/api/metrics');if(!state.authenticated)return;state.data=data;state.lastRefreshAt=Date.now();state.refreshFailed=false;
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
  }finally{state.refreshing=false}
}
document.addEventListener('visibilitychange',()=>{if(state.authenticated&&!document.hidden)startPolling()});
function pushHistory(key,value){const values=state.history[key]||(state.history[key]=[]);values.push([Date.now()/1000,Number(value)||0]);if(values.length>36)values.shift()}
function nodeFor(id){return state.data&&state.data.nodes&&state.data.nodes[id]}
function render(){
  if(!state.config)return;
  state.serviceRequest++;state.serviceEditing=false;
  state.modalKind='';state.modal=null;state.alertRequest++;state.alertLoading=false;
  app.innerHTML='<div class="shell"><aside class="sidebar"><div class="brand"><div class="brand-mark">◈</div><div><strong>TinyWatch</strong><small>INFRASTRUCTURE</small></div></div><nav class="nav" aria-label="Main navigation"><button class="active" data-view="overview"><span class="nav-icon">⌂</span><span>总览</span></button><button data-menu="assets"><span class="nav-icon">⌘</span><span>资产</span></button><button data-menu="settings"><span class="nav-icon">⚙</span><span>设置</span></button></nav></aside><main class="main"><header class="topbar"><div><div class="eyebrow">LIVE INFRASTRUCTURE</div><h1 class="page-title" id="page-title">系统总览</h1></div><div class="top-actions">'+languageSelector()+'<span class="status-pill" id="live-status"><i class="dot"></i><span id="live-status-label">实时采集</span></span><button class="icon-button" id="theme-toggle" title="切换主题" aria-label="Switch theme">◐</button><button class="icon-button" id="logout-button" title="退出登录" aria-label="Sign out">↗</button></div></header><section class="host-panel"><div class="host-panel-head"><div><h2>主机信息</h2><p>本地节点 · HOST PROFILE</p></div></div><div id="host-summary"></div></section><section class="overview" id="overview"></section><section id="fleet-health" class="fleet-health" aria-label="Asset health"></section><div class="section-head"><div><h2 id="panel-title">自定义监控面板</h2><p id="panel-description">拖拽卡片调整布局 · 数据每 2.5 秒更新</p></div><div class="panel-actions" id="panel-actions"><button type="button" class="button subtle" id="services-open">'+esc(ft('services'))+'</button><button type="button" class="button subtle" id="replay-open">' + esc(ft('replay')) + ' </button><button type="button" class="button subtle" id="alerts-open">Alerts · 0</button><button class="button subtle" id="assets-manage">管理资产</button><button class="button primary" id="add-widget">＋ 添加监控</button></div></div><section class="dashboard" id="dashboard" aria-live="polite"></section><div class="grid-footer" id="updated-at">正在连接监控节点…</div></main></div><div id="modal" class="modal-backdrop"></div>';
  document.documentElement.lang=state.language;localizeDOM(app);bindLanguageSelector();
  document.getElementById('theme-toggle').onclick=toggleTheme;
  document.getElementById('logout-button').onclick=logout;
  document.getElementById('assets-manage').onclick=showAssets;
  document.getElementById('services-open').onclick=()=>showServices();
  document.getElementById('replay-open').onclick=()=>showReplay('local');
  document.getElementById('alerts-open').onclick=()=>showAlerts();
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
  // Keep chart identities for unchanged cards and an open investigation.
  const local=nodeFor('local');if(!local||!local.metrics)return;
  const metricsLocal=local.metrics;const alive=Object.values(state.data.nodes).filter(node=>node.online).length;const total=Object.keys(state.data.nodes).length;
  const overview=document.getElementById('overview');const dashboard=document.getElementById('dashboard');
  const summary=document.getElementById('host-summary');
  const profileHTML='<article class="host-info-card">'+infoCard(metricsLocal)+'</article>';
  if(summary.dataset.profile!==profileHTML){summary.innerHTML=profileHTML;summary.dataset.profile=profileHTML;localizeDOM(summary)}
  overview.classList.remove('hidden');
  document.getElementById('panel-actions').classList.remove('hidden');
  document.getElementById('panel-title').textContent=tr('自定义监控面板');
  document.getElementById('panel-description').textContent=tr('拖拽卡片调整布局 · 数据每 2.5 秒更新');
  document.getElementById('side-host')?.remove();
  overview.innerHTML='<article class="stat"><div class="stat-label">CPU 使用率 <span class="tag good">'+metricsLocal.cpu.logical_cores+' 核</span></div><div class="stat-value">'+(metricsLocal.cpu.available?metricsLocal.cpu.percent:'—')+'<small>'+(metricsLocal.cpu.available?'%':'')+'</small></div><div class="stat-foot">'+(metricsLocal.cpu.cores.length?'每核心采样正常':(metricsLocal.cpu.available?'聚合采样':'当前系统未公开 CPU 计数'))+'</div></article><article class="stat"><div class="stat-label">内存使用 <span>RAM</span></div><div class="stat-value">'+(metricsLocal.memory.supported===false?'—':fmtBytes(metricsLocal.memory.used))+'</div><div class="stat-foot">'+(metricsLocal.memory.supported===false?tr('指标暂不可用'):'共 '+fmtBytes(metricsLocal.memory.total)+' · '+metricsLocal.memory.percent+'%')+'</div></article><article class="stat"><div class="stat-label">网络资产 <span class="tag good">在线</span></div><div class="stat-value">'+alive+'<small> / '+total+'</small></div><div class="stat-foot">含本地节点与已配置资产</div></article><article class="stat"><div class="stat-label">系统运行时长 <span>UPTIME</span></div><div class="stat-value" style="font-size:22px">'+esc(metricsLocal.info.uptime)+'</div><div class="stat-foot">'+esc(metricsLocal.info.os)+' '+esc(metricsLocal.info.release)+'</div></article>';
  localizeDOM(overview);
  drawFleetHealth();
  const assets=[{id:'local',name:metricsLocal.info.hostname}].concat(state.config.assets||[]);
  const widgets=(state.config.widgets||[]).filter(widget=>widget.metric!=='info');
  // Preserve card DOM so refreshes keep focus, selection and drag state.
  if(!state.dragged){
    const existing=new Map(Array.from(dashboard.children).map(card=>[card.dataset.widget,card]));
    for(const widget of widgets){
      const node=nodeFor(widget.node),asset=assets.find(item=>item.id===widget.node)||{id:widget.node,name:widget.node};
      let card=existing.get(widget.id);
      if(!card){card=document.createElement('article');card.className='widget '+(['processes','logins','dns'].includes(widget.metric)?'wide':'');card.draggable=!widget.transient;card.dataset.widget=widget.id}
      const details=node?.metrics||{},iface=widget.metric==='network'?(state.history[widget.node+':iface']||''):widget.metric==='disk'?(state.history[widget.node+':partition']||''):'';
      const selection=historySelectionKey(widget.node,widget.metric,iface),range=state.historyRanges[selection]||'1h';
      const cached=state.historical[historyCacheKey(widget.node,widget.metric,range,iface,state.historyCustom[selection])];
      const signature=JSON.stringify([widget,node?.online,node?.error,asset,state.language,details[widget.metric],details.collector_errors?.[widget.metric],
        widget.metric==='load'?details.info?.os:null,widget.metric==='load'?details.cpu?.logical_cores:null,
        details.collector_status?.[widget.metric],iface,range,state.historyCustom[selection],cached?.fetchedAt,
        state.config.history_retention_days,['cpu','memory','disk','network','load'].includes(widget.metric)&&!cached?state.lastRefreshAt:null]);
      // History expiry needs checking even when current measurements are static.
      historySelector(widget,node);
      if(card.dataset.signature!==signature){card.innerHTML=widgetCard(widget,node,asset);card.dataset.signature=signature;localizeDOM(card);bindWidget(card,widget)}
      existing.delete(widget.id);
      const position=widgets.indexOf(widget);
      if(dashboard.children[position]!==card)dashboard.insertBefore(card,dashboard.children[position]||null);
    }
    for(const card of existing.values())card.remove();
  }
  const chartIds=new Set(Array.from(document.querySelectorAll('[data-chart-id]')).map(chart=>chart.dataset.chartId));
  for(const id of Object.keys(state.chartData))if(!chartIds.has(id))delete state.chartData[id];
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
  else if(!node.online){
    const lastSuccess=node.last_success_at?new Date(node.last_success_at):null;
    const lastSuccessText=lastSuccess&&Number.isFinite(lastSuccess.getTime())?'<div class="metric-sub">'+tr('最后成功采样')+': '+esc(lastSuccess.toLocaleString(LANGUAGE_LOCALE[state.language]||'en-US'))+'</div>':'';
    content='<div class="asset-error">'+esc(ft(node.pending?'initializing':'connection_failed'))+(node.pending?'':' · '+esc(ft(node.error||'')))+lastSuccessText+(node.next_retry_at?'<p class="helper">'+esc(ft('next_retry'))+': '+esc(featureDate(node.next_retry_at))+'</p>':'')+'</div>';
  }
  else{
    const metric=node.metrics;
    const collectorError=metric.collector_errors&&metric.collector_errors[widget.metric];
    const unsupported=(widget.metric==='memory'&&metric.memory.supported===false)||
      (widget.metric==='disk'&&metric.disk.supported===false)||
      (widget.metric==='network'&&metric.network.supported===false)||
      (widget.metric==='load'&&(!metric.load||!metric.load.length));
    if(collectorError)content='<div class="asset-error">'+tr('指标暂不可用')+': '+esc(collectorError)+'</div>';
    else if(unsupported)content='<div class="empty">'+tr('指标暂不可用')+'</div>';
    else switch(widget.metric){
      case'cpu':content=cpuCard(metric,widget.node);break;case'memory':content=memoryCard(metric.memory,widget.node);break;
      case'network':content=networkCard(metric,widget);break;case'disk':content=diskCard(metric,widget);break;
      case'load':content=loadCard(metric,widget.node);break;case'processes':content=processCard(metric);break;
      case'logins':content=loginCard(metric);break;case'dns':content=dnsCard(metric);break;
      case'info':content=infoCard(metric);break;default:content='<div class="empty">未选择有效监控项</div>';
    }
  }
  if(node?.online&&node.status==='stale')content='<p class="asset-error">'+esc(ft('stale'))+'</p>'+content;
  const tools=(widget.metric==='network'&&node&&node.metrics?interfaceSelector(node.metrics.network,widget.node):'')+
    (historySelector(widget,node))+
    (widget.metric==='disk'&&node&&node.metrics?partitionSelector(node.metrics.disk,widget.node)+'<button class="select-mini" data-disk="'+esc(widget.node)+'">分区详情</button>':'')+
    (!widget.transient?'<button class="remove-widget" title="移除卡片" aria-label="Remove card">×</button>':'');
  return '<header class="widget-head"><div class="widget-title"><i>'+title[1]+'</i><div>'+title[0]+'<div class="widget-node">'+esc(asset.name)+'</div></div></div><div class="widget-tools">'+tools+'</div></header>'+content+collectorCaption(node?.metrics?.collector_status?.[widget.metric]);
}
function collectorCaption(status){
  if(!status)return '';
  return '<div class="helper">'+esc(ft('last_observed'))+': '+esc(featureDate(status.sampled_at))+' · '+esc(ft('cadence'))+': '+esc(status.interval_seconds)+' '+esc(ft('seconds'))+'</div>';
}
function cpuCard(metric,node){
  const cores=metric.cpu.cores||[];let bars='';
  for(const core of cores.slice(0,24))bars+='<div class="core"><label><span>'+esc(core.name.replace('cpu',''))+'</span><span>'+core.percent+'%</span></label><div class="track"><span style="width:'+pct(core.percent)+'%"></span></div></div>';
  const history=historyChartData(node,'cpu','');
  return '<div class="big-value">'+(metric.cpu.available?metric.cpu.percent:'—')+'<small>'+(metric.cpu.available?'% utilization':'')+'</small></div><div class="metric-sub">'+(cores.length?'逻辑核心实时占用':(metric.cpu.available?'聚合 CPU 计数':'当前平台未提供兼容的 CPU 计数接口'))+'</div>'+sparkline(history,'cpu')+(bars?'<div class="core-grid">'+bars+'</div>':'');
}
function memoryCard(memory,node){
  if(memory.supported===false)return '<div class="empty">'+tr('指标暂不可用')+'</div>';
  const history=historyChartData(node,'memory','');
  return '<div class="big-value">'+fmtBytes(memory.used)+'<small> / '+fmtBytes(memory.total)+'</small></div><div class="metric-sub">可用 '+fmtBytes(memory.available)+' · '+memory.percent+'%</div><div class="track" style="height:8px;margin-top:16px"><span style="width:'+pct(memory.percent)+'%"></span></div>'+sparkline(history,'memory');
}
function interfaceSelector(network,node){
  const items=network.interfaces||[];const selected=state.history[node+':iface']||'';
  return '<select class="select-mini iface-select" data-node="'+esc(node)+'" aria-label="Network interface"><option value="">全部网卡</option>'+items.map(item=>'<option value="'+esc(item.name)+'" '+(selected===item.name?'selected':'')+'>'+esc(item.name)+'</option>').join('')+'</select>';
}
function networkCard(metric,widget){
  const interfaces=metric.network.interfaces||[];const selected=state.history[widget.node+':iface'];const item=interfaces.find(entry=>entry.name===selected);
  if(selected&&!item)return '<div class="empty">'+esc(ft('unavailable'))+'</div>'+sparkline(historyChartData(widget.node,'network',selected),'network');
  const rx=item?item.rx_rate:metric.network.rx_rate;const tx=item?item.tx_rate:metric.network.tx_rate;
  const history=historyChartData(widget.node,'network',selected||'');
  return '<div class="duo"><div class="duo-box"><label>↓ 下载</label><strong>'+fmtBytes(rx)+'/s</strong></div><div class="duo-box"><label>↑ 上传</label><strong>'+fmtBytes(tx)+'/s</strong></div></div><div class="metric-sub" style="margin-top:9px">累计接收 '+fmtBytes(item?item.rx_total:interfaces.reduce((sum,entry)=>sum+entry.rx_total,0))+' · 发送 '+fmtBytes(item?item.tx_total:interfaces.reduce((sum,entry)=>sum+entry.tx_total,0))+'</div>'+sparkline(history,'network');
}
function diskCard(metric,widget){
  const parts=metric.disk.partitions||[],selected=state.history[widget.node+':partition']||'';
  const disk=selected?parts.find(part=>part.id===selected):metric.disk;
  if(!disk)return '<div class="empty">'+esc(ft('partition_missing'))+'</div>';
  const top=parts.slice().sort((a,b)=>b.percent-a.percent).slice(0,3),history=historyChartData(widget.node,'disk',selected);
  return '<div class="big-value">'+disk.percent+'<small>% used</small></div><div class="metric-sub">'+esc(selected?disk.mount:ft('aggregate'))+' · 已用 '+fmtBytes(disk.used)+' / '+fmtBytes(disk.total)+'</div><div class="track" style="height:7px;margin:12px 0 5px"><span style="width:'+pct(disk.percent)+'%"></span></div>'+top.map(item=>'<div class="disk-line"><span>'+esc(item.mount)+'</span><b class="'+(item.percent>=90?'asset-error':'')+'">'+item.percent+'% · '+fmtBytes(item.used)+' / '+fmtBytes(item.total)+'</b></div>').join('')+sparkline(history,'disk');
}
function partitionSelector(disk,node){
  const selected=state.history[node+':partition']||'',parts=disk.partitions||[];
  const missing=selected&&!parts.some(part=>part.id===selected);
  return '<select class="select-mini partition-select" aria-label="'+esc(ft('partition'))+'"><option value="">'+esc(ft('aggregate'))+'</option>'+
    (missing?'<option selected value="'+esc(selected)+'">'+esc(ft('partition_missing'))+'</option>':'')+
    parts.filter(part=>part.id).map(part=>'<option value="'+esc(part.id)+'" '+(selected===part.id?'selected':'')+'>'+esc(part.mount)+'</option>').join('')+'</select>';
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
  const iface=widget.metric==='network'?(state.history[widget.node+':iface']||''):widget.metric==='disk'?(state.history[widget.node+':partition']||''):'';
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
  const selection=historySelectionKey(node,metric,iface);
  const previous=state.historyRequests[selection];
  if(previous&&previous.key!==key)previous.controller.abort();
  const controller=new AbortController();state.historyRequests[selection]={key,controller};
  state.historyPending[key]=true;
  const query=new URLSearchParams({node,metric,range});if(iface)query.set(metric==='disk'?'partition':'iface',iface);
  if(range==='custom'){query.set('start',String(custom.start));query.set('end',String(custom.end))}
  api('/api/history?'+query.toString(),'GET',undefined,controller.signal).then(result=>{if(controller.signal.aborted||!state.authenticated)return;state.historical[key]={points:result.points||[],gaps:result.gaps||[],fetchedAt:Date.now()};
    const keys=Object.keys(state.historical);if(keys.length>256){keys.sort((a,b)=>state.historical[a].fetchedAt-state.historical[b].fetchedAt);for(const old of keys.slice(0,keys.length-256))delete state.historical[old]}draw()})
    .catch(error=>{if(error.name==='AbortError')return;if(error.status===401){state.authenticated=false;authScreen(false)}else toast(error.message)})
    .finally(()=>{delete state.historyPending[key];if(state.historyRequests[selection]?.controller===controller)delete state.historyRequests[selection]});
}
function historyChartData(node,metric,iface){
  const selection=historySelectionKey(node,metric,iface);const range=state.historyRanges[selection]||'1h';
  const cached=state.historical[historyCacheKey(node,metric,range,iface,state.historyCustom[selection])];
  if(cached){
    const index={cpu:1,memory:3,disk:3,load:1};
    return cached.points.map((point,position)=>({timestamp:Number(point[0]),value:metric==='network'?Number(point[1]||0)+Number(point[2]||0):Number(point[index[metric]]||0),rx:Number(point[1]||0),tx:Number(point[2]||0),gapBefore:position<(cached.gaps||[]).length?Boolean(cached.gaps[position]):undefined})).filter(point=>Number.isFinite(point.timestamp)&&Number.isFinite(point.value));
  }
  if(metric==='disk'&&iface)return []; // Aggregate live data cannot stand in for a selected partition.
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
function infoCard(m){const x=m.info;return '<div class="info-grid"><div class="info-item"><label>主机名</label><strong>'+esc(x.hostname)+'</strong></div><div class="info-item"><label>处理器</label><strong>'+esc(x.cpu)+' · '+x.logical_cores+' 核</strong></div><div class="info-item"><label>系统版本</label><strong>'+esc(x.system)+'</strong></div><div class="info-item"><label>内核版本</label><strong>'+esc(x.release)+' · '+esc(x.architecture)+'</strong></div><div class="info-item"><label>物理内存</label><strong>'+(x.memory_total?fmtBytes(x.memory_total):'—')+'</strong></div><div class="info-item"><label>系统运行时长</label><strong>'+esc(x.uptime)+'</strong></div><div class="info-item" style="grid-column:1/-1"><label>当前会话</label><strong>'+esc((x.sessions||[]).join(' · ')||'无活动终端会话或当前账户无读取权限')+'</strong></div></div>'}
function chartAxisMaximum(value){
  const rawStep=Math.max(value,0.000001)/4;
  const magnitude=Math.pow(10,Math.floor(Math.log10(rawStep)));
  const fraction=rawStep/magnitude;
  const niceFraction=fraction<=1?1:fraction<=2?2:fraction<=5?5:10;
  return niceFraction*magnitude*4;
}
function chartHasGap(previous,next){
  return typeof next.gapBefore==='boolean'?next.gapBefore:Number(next.timestamp)-Number(previous.timestamp)>CHART_GAP_SECONDS;
}
function downsampleHistory(samples,maximumPoints){
  const ordered=samples.slice().filter(point=>Number.isFinite(Number(point.timestamp))&&Number.isFinite(Number(point.value)))
    .sort((left,right)=>Number(left.timestamp)-Number(right.timestamp));
  if(ordered.length<=maximumPoints)return ordered;
  const gapPairs=[];
  for(let index=1;index<ordered.length;index++){
    if(chartHasGap(ordered[index-1],ordered[index]))gapPairs.push([index-1,index]);
  }
  // Reserve half the display budget for extrema, even with many outages.
  const maxGapPairs=Math.max(1,Math.floor((maximumPoints-2)/4));
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
  const indices=[...selected].sort((left,right)=>left-right);
  return indices.map((index,position)=>{
    if(!position)return ordered[index];
    let gapBefore=false;
    for(let current=indices[position-1]+1;current<=index;current++)if(chartHasGap(ordered[current-1],ordered[current])){gapBefore=true;break}
    return {...ordered[index],gapBefore};
  });
}
function chartTimeLabel(timestamp,span,includeYear){
  const date=new Date(timestamp*1000);
  if(!Number.isFinite(date.getTime()))return '—';
  const locale=LANGUAGE_LOCALE[state.language]||'en-US';
  return span<86400
    ?date.toLocaleTimeString(locale,{hour:'2-digit',minute:'2-digit'})
    :date.toLocaleDateString(locale,includeYear?{year:'2-digit',month:'2-digit',day:'2-digit'}:{month:'2-digit',day:'2-digit'});
}
function sparkline(samples,metric,windowRange){
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
  const firstTime=windowRange?windowRange.start:hasTimeRange?timestamps[0]:0;
  const timeSpan=windowRange?windowRange.end-windowRange.start:hasTimeRange?timestamps[timestamps.length-1]-firstTime:0;
  const firstDate=new Date(timestamps[0]*1000),lastDate=new Date(timestamps[timestamps.length-1]*1000);
  const crossesYear=Number.isFinite(firstDate.getTime())&&Number.isFinite(lastDate.getTime())&&firstDate.getFullYear()!==lastDate.getFullYear();
  const pointCount=points.length;
  points=points.map((point,index)=>{
    const value=Math.max(0,Number(point.value)||0);
    const x=pointCount===1&&!windowRange?plotLeft+plotWidth/2:plotLeft+((hasTimeRange||windowRange)?(timestamps[index]-firstTime)/timeSpan:index/(pointCount-1))*plotWidth;
    const y=plotBottom-Math.min(1,value/axisMaximum)*plotHeight;
    return {...point,x,y};
  });
  const ticks=Array.from({length:5},(_,index)=>axisMaximum*(4-index)/4);
  const formatY=value=>percentageMetric
    ?new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{maximumFractionDigits:0}).format(value)+'%'
    :metric==='latency'?new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{maximumFractionDigits:1}).format(value)+' ms'
    :metric==='network'?fmtBytes(value)+'/s'
    :new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{maximumFractionDigits:2}).format(value);
  const grid=ticks.map(value=>{
    const y=plotBottom-(value/axisMaximum)*plotHeight;
    return '<line class="chart-grid" x1="'+plotLeft+'" y1="'+y.toFixed(1)+'" x2="'+plotRight+'" y2="'+y.toFixed(1)+'"></line><text class="chart-label" x="'+(plotLeft-7)+'" y="'+(y+3).toFixed(1)+'" text-anchor="end">'+formatY(value)+'</text>';
  }).join('');
  const xTicks=pointCount===1&&!windowRange?[{x:points[0].x,timestamp:points[0].timestamp,anchor:'middle',position:'single'}]:[
    {x:plotLeft,timestamp:windowRange?windowRange.start:points[0].timestamp,anchor:'start',position:'first'},
    {x:(plotLeft+plotRight)/2,timestamp:(hasTimeRange||windowRange)?(firstTime+timeSpan/2):points[Math.floor(pointCount/2)].timestamp,anchor:'middle',position:'middle'},
    {x:plotRight,timestamp:windowRange?windowRange.end:points[pointCount-1].timestamp,anchor:'end',position:'last'}
  ];
  const xLabels=xTicks.map(tick=>'<line class="chart-grid chart-grid-vertical chart-grid-'+tick.position+'" x1="'+tick.x.toFixed(1)+'" y1="'+plotTop+'" x2="'+tick.x.toFixed(1)+'" y2="'+plotBottom+'"></line><text class="chart-label chart-label-x chart-label-'+tick.position+'" x="'+tick.x.toFixed(1)+'" y="125" text-anchor="'+tick.anchor+'">'+chartTimeLabel(Number(tick.timestamp),(hasTimeRange||windowRange)?timeSpan:0,crossesYear)+'</text>').join('');
  const segments=[];
  points.forEach(point=>{
    const current=segments[segments.length-1];
    if(!current||chartHasGap(current[current.length-1],point))segments.push([point]);
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
  let hideTimer=null,pointerFrame=null;
  const hide=()=>{
    if(pointerFrame!==null){cancelAnimationFrame(pointerFrame);pointerFrame=null}
    clearTimeout(hideTimer);tooltip.classList.remove('visible');
    const marker=chart.querySelector('.chart-hover'),crosshair=chart.querySelector('.chart-crosshair');
    if(marker){marker.setAttribute('cx','-10');marker.setAttribute('cy','-10')}
    if(crosshair){crosshair.setAttribute('x1','-10');crosshair.setAttribute('x2','-10')}
  };
  const showPoint=(point,index,clientX,clientY)=>{
    const rect=chart.getBoundingClientRect();if(!rect.width)return;
    chart.dataset.activeIndex=String(index);
    if(chart.closest('.replay-charts'))syncReplayCursor(point.timestamp);
    const date=new Date(point.timestamp*1000);const dateText=Number.isFinite(date.getTime())?date.toLocaleString(LANGUAGE_LOCALE[state.language]||'en-US'):'—';
    let valueText;
    if(data.metric==='network')valueText=point.rx==null?fmtBytes(point.value)+'/s':fmtBytes(point.value)+'/s  (↓ '+fmtBytes(point.rx||0)+'/s · ↑ '+fmtBytes(point.tx||0)+'/s)';
    else if(data.metric==='latency')valueText=Number(point.value).toFixed(1)+' ms';
    else if(data.metric==='load')valueText=Number(point.value).toFixed(2);
    else valueText=Number(point.value).toFixed(1)+'%';
    tooltip.textContent=dateText+'\n'+alertMetricLabel(data.metric)+': '+valueText;tooltip.classList.add('visible');
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
  chart.addEventListener('pointermove',event=>{if(pointerFrame!==null)cancelAnimationFrame(pointerFrame);pointerFrame=requestAnimationFrame(()=>{pointerFrame=null;if(chart.isConnected)showPointer(event)})});
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
  const partition=el.querySelector('.partition-select');if(partition)partition.onchange=()=>{state.history[w.node+':partition']=partition.value;draw()};
  const iface=el.querySelector('.iface-select');if(iface)iface.onchange=()=>{state.history[w.node+':iface']=iface.value;draw()};
  const range=el.querySelector('.history-select');if(range)range.onchange=()=>{const selection=historySelectionKey(w.node,w.metric,range.dataset.interface||'');if(range.value==='custom'){draw();showHistoryRange(w.node,w.metric,range.dataset.interface||'');return}delete state.historyCustom[selection];state.historyRanges[selection]=range.value;draw()};
  const custom=el.querySelector('.history-custom');if(custom)custom.onclick=()=>showHistoryRange(w.node,w.metric,custom.dataset.interface||'');
  const disk=el.querySelector('[data-disk]');if(disk)disk.onclick=()=>showDisks(w.node)
}
async function saveConfig(){await api('/api/config','POST',{assets:state.config.assets,widgets:state.config.widgets,theme:state.config.theme,history_retention_days:state.config.history_retention_days});state.config=await api('/api/config')}
function modal(content,wide){state.serviceRequest++;state.serviceLoading=false;state.replayRequest++;state.replayController?.abort();state.modalKind='';state.alertRequest++;state.alertLoading=false;const box=document.getElementById('modal');box.className='modal-backdrop open';box.innerHTML='<section class="modal '+(wide?'wide-modal':'')+'">'+content+'</section>';localizeDOM(box);box.onclick=e=>{if(e.target===box)closeModal()};const close=box.querySelectorAll('[data-close]');close.forEach(x=>x.onclick=closeModal);state.modal=box}
function closeModal(){state.serviceRequest++;state.replayRequest++;state.replayController?.abort();document.getElementById('chart-tooltip')?.classList.remove('visible');state.modalKind='';state.alertRequest++;state.alertLoading=false;const box=document.getElementById('modal');if(box){box.className='modal-backdrop';box.innerHTML=''}state.modal=null}
async function showDisks(id){
  const node=nodeFor(id);if(!node?.metrics)return;
  const rows=node.metrics.disk.partitions||[];
  modal(featureHeader(ft('capacity_title')+' · '+node.name,ft('capacity_help'))+
    '<div class="table-scroll"><table class="data-table"><thead><tr>'+['disk_mount','disk_device','disk_filesystem','disk_space','disk_inodes','capacity_estimated'].map(key=>'<th>'+esc(ft(key))+'</th>').join('')+'</tr></thead><tbody>'+rows.map(part=>'<tr><td>'+esc(part.mount)+'</td><td>'+esc(part.device)+'</td><td>'+esc(part.filesystem)+'</td><td>'+esc(fmtBytes(part.used))+' / '+esc(fmtBytes(part.total))+'<small> · '+esc(part.percent)+'%</small></td><td>'+(part.inode_percent==null?'—':esc(part.inode_percent)+'%')+'</td><td data-capacity="'+esc(part.id||'')+'">'+esc(ft('loading'))+'</td></tr>').join('')+'</tbody></table></div><p id="capacity-error" class="error-message" role="alert"></p>',true);
  state.modalKind='capacity';const panel=state.modal,request=state.capacityRequest=(state.capacityRequest||0)+1;
  try{
    const result=await api('/api/capacity?node='+encodeURIComponent(id));
    if(state.modal!==panel||state.modalKind!=='capacity'||request!==state.capacityRequest)return;
    panel.querySelectorAll('[data-capacity]').forEach(cell=>{
      const estimate=result.partitions[cell.dataset.capacity];
      cell.textContent=estimate?.status==='estimated'?String(estimate.days_remaining):ft('capacity_'+(estimate?.status||'insufficient'));
      if(estimate?.growth_per_day!=null){const detail=document.createElement('p');detail.className='helper';detail.textContent=ft('capacity_rate')+': '+(estimate.growth_per_day<0?'−':'')+fmtBytes(Math.abs(estimate.growth_per_day));cell.append(detail)}
    });
  }catch(error){if(state.modal===panel&&state.modalKind==='capacity'&&request===state.capacityRequest){panel.querySelectorAll('[data-capacity]').forEach(cell=>cell.textContent='—');document.getElementById('capacity-error').textContent=tr(error.message)}}
}

function showAddWidget(){const assets=[{id:'local',name:nodeFor('local')?.name||'本机'}].concat(state.config.assets||[]);modal('<header class="modal-head"><h3>添加监控卡片</h3><button class="close" data-close>×</button></header><form id="widget-form"><div class="form-grid"><div class="field full"><label>网络资产</label><select id="widget-node">'+assets.map(a=>'<option value="'+esc(a.id)+'">'+esc(a.name)+'</option>').join('')+'</select></div><div class="field full"><label>监控项目</label><select id="widget-metric">'+Object.entries(metrics).filter(([key])=>key!=='info').map(([k,v])=>'<option value="'+k+'">'+v[0]+'</option>').join('')+'</select></div></div><div class="error-message" id="widget-error"></div><div class="modal-actions"><button type="button" class="button subtle" data-close>取消</button><button class="button primary">添加卡片</button></div></form>');document.getElementById('widget-form').onsubmit=async e=>{e.preventDefault();if(state.config.widgets.length>=32){document.getElementById('widget-error').textContent=tr('最多添加 32 张卡片');return}const node=document.getElementById('widget-node').value,metric=document.getElementById('widget-metric').value;state.config.widgets.push({id:crypto.randomUUID?crypto.randomUUID():('w-'+Date.now()),node:node,metric:metric});closeModal();draw();try{await saveConfig()}catch(err){toast(err.message)}}}
function showHistorySettings(){showSettings()}
function showSettings(){
  const current=Number(state.config.history_retention_days)||7;
  const retention=[1,3,7,14,30].map(value=>'<option value="'+value+'" '+(value===current?'selected':'')+'>'+tr(value+' 天')+'</option>').join('');
  const themes=[['dark','深色'],['light','浅色']].map(([value,label])=>'<option value="'+value+'" '+(state.config.theme===value?'selected':'')+'>'+tr(label)+'</option>').join('');
  const languages=Object.entries(LANGUAGE_NAMES).map(([code,name])=>'<option value="'+code+'" '+(state.language===code?'selected':'')+'>'+name+'</option>').join('');
  modal('<header class="modal-head"><div><h3>设置</h3><div class="helper">配置语言、外观和历史数据保留期限。</div></div><button class="close" data-close aria-label="Close">×</button></header><form id="settings-form"><div class="form-grid"><div class="field"><label for="settings-language">Language</label><select id="settings-language">'+languages+'</select></div><div class="field"><label for="settings-theme">主题</label><select id="settings-theme">'+themes+'</select></div><div class="field full"><label for="retention-days">数据保留期限 · 保留时间</label><select id="retention-days">'+retention+'</select></div></div><div class="helper">历史样本每分钟保存到本地 JSON 数据库。</div><div class="helper">'+esc(ft('history_policy'))+'</div><div class="helper">缩短保留期限会立即删除超出期限的旧数据。</div><div class="field full"><label class="checkbox-label"><input id="settings-flight" type="checkbox" '+(state.config.flight_enabled?'checked':'')+'>'+esc(ft('flight_enable'))+'</label><p class="helper">'+esc(ft('flight_help'))+'</p></div><div class="field full"><a class="button subtle" href="/api/backup" download="tinywatch-backup.zip">'+esc(ft('download_backup'))+'</a><p class="helper">'+esc(ft('backup_help'))+'</p></div><div class="error-message" id="settings-error"></div><div class="modal-actions"><button type="button" class="button subtle" data-close>取消</button><button type="submit" class="button primary">保存设置</button></div></form>');
  document.getElementById('settings-form').onsubmit=async event=>{
    event.preventDefault();const nextLanguage=document.getElementById('settings-language').value;
    const nextTheme=document.getElementById('settings-theme').value;const nextDays=Number(document.getElementById('retention-days').value);
    try{
      await api('/api/config','POST',{assets:state.config.assets,widgets:state.config.widgets,theme:nextTheme,history_retention_days:nextDays,flight_enabled:document.getElementById('settings-flight').checked});
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
  const rows=assets.map(asset=>{
    const node=nodeFor(asset.id),lastSuccess=node&&node.last_success_at?new Date(node.last_success_at):null;
    const stateLabel=node?ft(node.status|| (node.online?'healthy':'connection_failed')):ft('initializing');
    const status=node?'<span class="tag '+(node.online&&node.status!=='stale'?'good':node.pending?'':'bad')+'">'+esc(stateLabel)+'</span>':'<span class="tag">'+stateLabel+'</span>';
    const sample=lastSuccess&&Number.isFinite(lastSuccess.getTime())?'<div class="metric-sub">'+tr('最后成功采样')+': '+esc(lastSuccess.toLocaleString(LANGUAGE_LOCALE[state.language]||'en-US'))+'</div>':'';
    return '<div class="disk-line"><span><strong>'+esc(asset.name)+'</strong> '+status+
      (asset.secure_transport?'':' <span class="tag">HTTP</span>')+
      '<div class="metric-sub">'+esc(asset.url)+'</div>'+sample+'</span><button class="button danger" data-remove="'+esc(asset.id)+'">移除</button></div>';
  }).join('');
  modal('<header class="modal-head"><div><h3>网络资产</h3><div class="helper">配置远程 TinyWatch 节点。每个节点需在“代理令牌”处填入目标主机生成的令牌。</div></div><button class="close" data-close>×</button></header><div class="feature-toolbar"><button type="button" class="button subtle" id="assets-diagnostics">'+esc(ft('diagnostics'))+'</button></div><div>'+rows+'</div><form id="asset-form" style="margin-top:16px"><div class="form-grid"><div class="field"><label>资产名称</label><input id="asset-name" required maxlength="80" placeholder="例如：edge-node-01"></div><div class="field"><label>服务地址</label><input id="asset-url" required placeholder="192.168.1.10:8765"></div><div class="field full"><label>代理令牌</label><input id="asset-password" required autocomplete="off" placeholder="在目标节点设置页复制代理令牌"></div></div><div class="helper">'+esc(ft('http_help'))+'</div><div class="error-message" id="asset-error"></div><div class="modal-actions"><button class="button primary">添加资产</button></div></form><div class="helper">本机代理令牌（复制到其他节点的资产配置中）：<br><code style="overflow-wrap:anywhere">'+esc(state.config.agent_token)+'</code></div>');
  document.getElementById('assets-diagnostics').onclick=()=>showDiagnostics();
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
const FEATURE_MESSAGES = {
  preview_rule: ["Preview rule", "试算规则", "ルール試算", "Simuler la règle", "Проверить правило", "Regel simulieren"],
  preview_help: ["Only raw samples are evaluated. Compacted or missing intervals are unknown; historical baselines use earlier data only.", "仅评估原始样本；压缩或缺失时段视为未知，历史基线只使用当时之前的数据。", "元サンプルのみ評価。圧縮・欠測は不明。基準は過去データのみ。", "Seuls les échantillons bruts sont évalués. Intervalles compactés ou absents : inconnus. Référence fondée sur le passé.", "Оцениваются исходные данные. Сжатые и пропущенные интервалы неизвестны. База использует только прошлые данные.", "Nur Rohdaten werden ausgewertet. Verdichtete und fehlende Zeiten sind unbekannt; Basis nur aus früheren Daten."],
  preview_count: ["Triggers in observed data", "已观测数据中的触发次数", "観測データの発火数", "Déclenchements observés", "Срабатывания по данным", "Auslösungen in beobachteten Daten"],
  preview_coverage: ["Evaluable coverage", "可评估覆盖率", "評価可能率", "Couverture évaluable", "Доля пригодных данных", "Auswertbare Abdeckung"],
  preview_unknown: ["Unknown interval", "未知时段", "不明期間", "Intervalle inconnu", "Неизвестный интервал", "Unbekannter Zeitraum"],
  preview_uncertain: ["Includes unknown intervals", "包含未知时段", "不明期間を含む", "Inclut des intervalles inconnus", "Включает неизвестные интервалы", "Enthält unbekannte Zeiten"],
  preview_observed: ["Observed duration", "有观测依据的持续时间", "観測された時間", "Durée observée", "Наблюдаемая длительность", "Beobachtete Dauer"],
  capacity_title: ["Disk capacity outlook", "磁盘容量趋势", "ディスク容量予測", "Prévision de capacité", "Прогноз диска", "Kapazitätsprognose"],
  capacity_help: ["Uses seven days of retained partition samples. Estimates require four sufficiently sampled days, stable capacity and a consistent growth trend.", "使用近七天分区样本；至少四天采样充分、容量不变且增长趋势稳定时才估算。", "過去7日のサンプル。十分な4日分、不変の容量、安定した増加が必要。", "Utilise sept jours de données. Nécessite quatre jours suffisamment couverts, une capacité fixe et une croissance stable.", "Данные за семь дней. Нужны четыре дня достаточных измерений, постоянная ёмкость и устойчивый рост.", "Sieben Tage Daten. Benötigt vier ausreichend erfasste Tage, konstante Kapazität und stabilen Zuwachs."],
  capacity_estimated: ["Estimated remaining days", "预计剩余天数", "推定残日数", "Jours restants estimés", "Оценка оставшихся дней", "Geschätzte Resttage"],
  capacity_insufficient: ["Insufficient history", "历史数据不足", "履歴不足", "Historique insuffisant", "Недостаточно истории", "Zu wenig Verlauf"],
  percentage_points: ['percentage points', '个百分点', 'ポイント', 'points de pourcentage', 'процентных пунктов', 'Prozentpunkte'],
  worst_partition: ['Worst partition', '占用最高的分区', '使用率最大のパーティション', 'Partition la plus utilisée', 'Наиболее заполненный раздел', 'Am stärksten belegte Partition'],
  sample_failures: ["Failed checks", "失败检查次数", "失敗したチェック", "Vérifications échouées", "Неуспешные проверки", "Fehlgeschlagene Prüfungen"],
  compare_change: ["Compare around cursor", "以光标时间对比", "カーソル前後を比較", "Comparer autour du curseur", "Сравнить вокруг курсора", "Um Cursor vergleichen"],
  comparison: ["Before and after", "变更前后对比", "変更前後の比較", "Avant et après", "До и после", "Vorher und nachher"],
  comparison_help: ["Raw resource samples only. Low coverage or an unfinished window limits interpretation. Service statistics use fully contained five-minute buckets and include failed probes. Observed changes do not establish causation.", "资源仅使用原始样本；覆盖不足或窗口未结束时，结论受限。服务统计使用完整落在窗口内的五分钟桶，包含失败探测。变化不等于因果关系。", "リソースは生サンプルのみ。欠測や未完了の期間に注意。サービスは期間内の完全な5分バケットで失敗も含みます。因果関係は示しません。", "Mesures brutes uniquement. Couverture faible ou fenêtre inachevée limite l’analyse. Services : compartiments complets de cinq minutes, échecs inclus. Pas de preuve de causalité.", "Только исходные измерения. Низкое покрытие и незавершённый период ограничивают выводы. Сервисы: полные пятиминутные интервалы, включая сбои. Причинность не устанавливается.", "Nur Rohmesswerte. Geringe Abdeckung oder offene Zeitfenster begrenzen die Aussage. Dienste: vollständige Fünfminutenblöcke mit Fehlversuchen. Keine Kausalitätsaussage."],
  before: ["Before", "之前", "前", "Avant", "До", "Vorher"],
  after: ["After", "之后", "後", "Après", "После", "Nachher"],
  sample_median: ["Sample median", "样本中位数", "サンプル中央値", "Médiane des mesures", "Медиана измерений", "Stichprobenmedian"],
  peak_value: ["Peak", "峰值", "最大値", "Maximum", "Максимум", "Spitzenwert"],
  coverage: ["Coverage", "覆盖率", "カバー率", "Couverture", "Покрытие", "Abdeckung"],
  change_delta: ["Median change", "中位数变化", "中央値の変化", "Variation de médiane", "Изменение медианы", "Medianänderung"],
  low_coverage: ["Incomplete evidence", "数据依据不足", "データ不足", "Données insuffisantes", "Недостаточно данных", "Unzureichende Daten"],
  window_minutes: ["Window on each side (minutes)", "前后各取（分钟）", "前後の期間（分）", "Fenêtre de chaque côté (minutes)", "Период с каждой стороны (минуты)", "Zeitraum je Seite (Minuten)"],
  change_time: ["Change time", "变更时间", "変更時刻", "Heure du changement", "Время изменения", "Änderungszeit"],
  new_incidents: ["New incidents", "新触发事件", "新規インシデント", "Nouveaux incidents", "Новые инциденты", "Neue Vorfälle"],
  resolved_incidents: ["Resolved incidents", "恢复事件", "解決したインシデント", "Incidents résolus", "Закрытые инциденты", "Behobene Vorfälle"],
  flight_record: ["Incident recording", "故障前后记录", "障害前後の記録", "Enregistrement d’incident", "Запись инцидента", "Vorfallaufzeichnung"],
  flight_help: ["Local only: two-second resource samples, up to five minutes before and two minutes after a trigger. Process values retain their collector timestamp. Missing samples remain gaps. Up to 16 clips within a 2 MiB budget.", "仅本机：资源两秒采样，保留触发前最多五分钟与触发后两分钟。进程数据保留原采样时间，缺失数据保持断点。最多 16 段，存储预算 2 MiB。", "ローカルのみ。2秒サンプル、発生前最大5分・発生後2分。プロセスの収集時刻を保持。欠測は空白。最大16記録、2 MiB以内。", "Local uniquement : mesures toutes les deux secondes, cinq minutes avant et deux après. Horodatage des processus conservé, lacunes visibles. Jusqu’à 16 extraits, budget de 2 MiB.", "Только локально: измерения каждые две секунды, до пяти минут до и двух после события. Время сбора процессов сохраняется, пропуски видны. До 16 записей, бюджет 2 MiB.", "Nur lokal: Messwerte alle zwei Sekunden, bis fünf Minuten davor und zwei danach. Prozesswerte behalten ihren Erfassungszeitpunkt. Lücken bleiben sichtbar. Bis 16 Ausschnitte, Budget 2 MiB."],
  flight_enable: ["Enable local incident recording", "开启本机故障前后记录", "ローカル障害記録を有効化", "Activer l’enregistrement local", "Включить локальную запись инцидентов", "Lokale Vorfallaufzeichnung aktivieren"],
  recording: ["Recording", "记录中", "記録中", "Enregistrement", "Запись", "Aufzeichnung"],
  complete: ["Complete", "已结束", "完了", "Terminé", "Завершено", "Abgeschlossen"],
  stopped: ["Stopped", "已停止", "停止", "Arrêté", "Остановлено", "Gestoppt"],
  worker_flight: ["Incident recorder", "故障记录采样", "障害記録", "Enregistreur d’incidents", "Запись инцидентов", "Vorfallaufzeichnung"],
  max_runtime: ["Maximum runtime (minutes)", "最长运行时间（分钟）", "最大実行時間（分）", "Durée maximale (minutes)", "Максимальное время (минуты)", "Maximale Laufzeit (Minuten)"],
  run_history: ["Recent runs (up to 50)", "近期运行（最多 50 条）", "最近の実行（最大50件）", "Exécutions récentes (50 maximum)", "Последние запуски (до 50)", "Letzte Ausführungen (bis 50)"],
  run_running: ["Running", "运行中", "実行中", "En cours", "Выполняется", "Läuft"],
  run_success: ["Succeeded", "成功", "成功", "Réussite", "Успешно", "Erfolgreich"],
  run_failed: ["Failed", "失败", "失敗", "Échec", "Ошибка", "Fehlgeschlagen"],
  run_timeout: ["Timed out", "运行超时", "タイムアウト", "Délai dépassé", "Время истекло", "Zeitüberschreitung"],
  overlapping: ["Overlapping run", "重叠运行", "重複実行", "Exécution simultanée", "Пересекающийся запуск", "Überlappende Ausführung"],
  late_completion: ["Completed after timeout", "超时后结束", "タイムアウト後に完了", "Terminé après expiration", "Завершён после тайм-аута", "Nach Zeitlimit abgeschlossen"],
  run_result: ["Result", "结果", "結果", "Résultat", "Результат", "Ergebnis"],
  run_duration: ["Duration (ms)", "耗时（毫秒）", "所要時間（ms）", "Durée (ms)", "Длительность (мс)", "Dauer (ms)"],
  task_failed: ["Task reported failure", "任务上报失败", "タスクが失敗を報告", "Échec signalé par la tâche", "Задача сообщила об ошибке", "Aufgabe meldet Fehler"],
  task_timeout: ["Task runtime exceeded its limit", "任务运行超时", "最大実行時間を超過", "Durée maximale dépassée", "Превышено время выполнения", "Maximale Laufzeit überschritten"],
  tls_certificate: ['TLS certificate', 'TLS 证书', 'TLS 証明書', 'Certificat TLS', 'Сертификат TLS', 'TLS-Zertifikat'],
  request_timeout: ['Asset request exceeded its deadline', '资产请求超出时间限制', 'アセット要求が制限時間を超過', 'Délai de requête de l’hôte dépassé', 'Превышено время запроса узла', 'Zeitlimit der Host-Anfrage überschritten'],
  initializing: ["Initializing", "初始化中", "初期化中", "Initialisation", "Инициализация", "Initialisierung"],
  download_backup: ["Download backup", "下载备份", "バックアップをダウンロード", "Télécharger une sauvegarde", "Скачать резервную копию", "Sicherung herunterladen"],
  backup_help: ["Includes history, configuration and credentials. Restore offline into a new directory with --restore-backup.", "包含历史、配置和凭证。使用 --restore-backup 离线恢复到新目录。", "履歴、設定、認証情報を含みます。--restore-backup で新しいディレクトリに復元してください。", "Contient historique, configuration et identifiants. Restaurer hors ligne dans un nouveau dossier avec --restore-backup.", "Содержит историю, настройки и учётные данные. Восстановление через --restore-backup в новый каталог.", "Enthält Verlauf, Einstellungen und Zugangsdaten. Mit --restore-backup offline in ein neues Verzeichnis wiederherstellen."],
  next_retry: ["Next attempt", "下次尝试", "次の試行", "Prochaine tentative", "Следующая попытка", "Nächster Versuch"],
  certificate_expiring: ["Certificate expires soon", "证书即将到期", "証明書の期限が近づいています", "Le certificat expire bientôt", "Сертификат скоро истекает", "Zertifikat läuft bald ab"],
  certificate_invalid: ["Certificate verification failed", "证书验证失败", "証明書検証に失敗", "Échec de vérification du certificat", "Ошибка проверки сертификата", "Zertifikatsprüfung fehlgeschlagen"],
  certificate_until: ["Certificate valid until", "证书有效期至", "証明書の有効期限", "Certificat valable jusqu’au", "Сертификат действителен до", "Zertifikat gültig bis"],
  certificate_warning: ["Warn before expiry (days)", "到期前提醒（天）", "期限前の通知（日）", "Alerte avant expiration (jours)", "Предупредить до истечения (дни)", "Vor Ablauf warnen (Tage)"],
  days_remaining: ["Days remaining", "剩余天数", "残り日数", "Jours restants", "Осталось дней", "Verbleibende Tage"],
  dns_failed: ["DNS resolution failed", "DNS 解析失败", "DNS 解決に失敗", "Échec de résolution DNS", "Ошибка разрешения DNS", "DNS-Auflösung fehlgeschlagen"],
  tls_failed: ["TLS handshake failed", "TLS 握手失败", "TLS ハンドシェイクに失敗", "Échec de négociation TLS", "Ошибка согласования TLS", "TLS-Handshake fehlgeschlagen"],
  probe_timeout: ["Probe timed out", "检查超时", "チェックがタイムアウト", "Délai de vérification dépassé", "Время проверки истекло", "Zeitüberschreitung der Prüfung"],
  capacity_capacity_changed: ["Capacity changed", "容量发生变化", "容量変更", "Capacité modifiée", "Ёмкость изменилась", "Kapazität geändert"],
  capacity_data_gap: ["History has long gaps", "历史存在长时间缺测", "長い欠測あり", "Longues lacunes", "Длительные пропуски", "Lange Datenlücken"],
  capacity_unstable: ["Unstable growth trend", "增长趋势不稳定", "増加傾向が不安定", "Croissance instable", "Неустойчивый рост", "Instabiler Zuwachs"],
  capacity_no_growth: ["No sustained growth", "没有持续增长", "継続的増加なし", "Pas de croissance durable", "Нет устойчивого роста", "Kein anhaltender Zuwachs"],
  capacity_long_horizon: ["Beyond one-year horizon", "超过一年预测范围", "1年の範囲外", "Au-delà d’un an", "За пределами года", "Außerhalb eines Jahres"],
  capacity_stale: ["Samples are stale", "样本已过期", "古いサンプル", "Échantillons anciens", "Устаревшие данные", "Veraltete Daten"],
  capacity_rate: ["Growth per day", "每日增长", "1日増加", "Croissance par jour", "Рост в день", "Zuwachs pro Tag"],
  disk_mount: ["Mount", "挂载点", "マウント", "Montage", "Точка монтирования", "Mountpunkt"],
  disk_device: ["Device", "设备", "デバイス", "Périphérique", "Устройство", "Gerät"],
  disk_filesystem: ["Filesystem", "文件系统", "ファイルシステム", "Système de fichiers", "Файловая система", "Dateisystem"],
  disk_space: ["Used / total", "已用 / 总量", "使用 / 合計", "Utilisé / total", "Использовано / всего", "Belegt / gesamt"],
  disk_inodes: ["Inode usage", "inode 占用", "inode 使用率", "Utilisation inode", "Использование inode", "Inode-Belegung"],
  worker_assets: ["Asset sampling", "资产采样", "資産収集", "Collecte des hôtes", "Сбор с узлов", "Hosterfassung"],
  worker_restarts: ["Restarts", "重试次数", "再起動数", "Redémarrages", "Перезапуски", "Neustarts"],
  worker_restarting: ["Retrying", "等待重试", "再試行中", "Nouvelle tentative", "Повторная попытка", "Erneuter Versuch"],
  encoded_days: ["Days encoded in last save", "上次保存编码天数", "前回の符号化日数", "Jours encodés au dernier enregistrement", "Дней обработано при записи", "Zuletzt kodierte Tage"],

  heartbeat_overdue: ["Task success report overdue", "任务成功上报已超期", "成功報告の期限超過", "Rapport de réussite en retard", "Просрочен отчёт об успехе", "Erfolgsmeldung überfällig"],
  worker_notifications: ["Notification delivery", "通知投递", "通知送信", "Envoi des notifications", "Доставка уведомлений", "Nachrichtenzustellung"],
  worker_services: ["Service checks", "服务检查", "サービス確認", "Contrôles de service", "Проверки сервисов", "Dienstprüfungen"],
  worker_details: ["Host details", "主机详情", "ホスト詳細", "Détails de l’hôte", "Данные хоста", "Hostdetails"],
  worker_history: ["History sampler", "历史采样", "履歴収集", "Collecte historique", "Сбор истории", "Verlaufserfassung"],
  monitor_disabled: ["Monitor disabled", "监控已停用", "監視を無効化", "Moniteur désactivé", "Монитор отключён", "Monitor deaktiviert"],
  heartbeats: ["Scheduled tasks", "定时任务", "定期タスク", "Tâches planifiées", "Плановые задачи", "Geplante Aufgaben"],
  heartbeat_help: ["Report start, success or fail with a task token and run_id. Running tasks have a runtime limit; idle tasks retain the expected success deadline.", "使用任务令牌与 run_id 上报开始、成功或失败。运行中的任务有时限，未运行的任务按成功上报周期检查。", "トークンと run_id で start、success、fail を報告。実行時間上限と成功報告期限を監視します。", "Signalez start, success ou fail avec le jeton et run_id. Limite de durée en cours, échéance de réussite au repos.", "Передавайте start, success или fail с токеном и run_id. Для выполнения действует лимит, для ожидания — срок отчёта об успехе.", "Start, success oder fail mit Token und run_id melden. Laufzeitlimit für aktive Aufgaben, Erfolgsfrist für wartende Aufgaben."],
  heartbeat_token: ["Task token", "任务令牌", "タスクトークン", "Jeton de tâche", "Токен задачи", "Aufgaben-Token"],
  heartbeat_grace: ["Grace period (minutes)", "宽限期（分钟）", "猶予（分）", "Tolérance (minutes)", "Отсрочка (минуты)", "Toleranz (Minuten)"],
  heartbeat_interval: ["Expected interval (minutes)", "预期周期（分钟）", "周期（分）", "Intervalle prévu (minutes)", "Ожидаемый интервал (минуты)", "Erwartetes Intervall (Minuten)"],
  heartbeat_endpoint: ["POST /api/heartbeat with X-TinyWatch-Heartbeat. JSON: {\"event\":\"start\",\"run_id\":\"backup-001\"}; finish with success or fail and the same run_id. Legacy {\"duration_ms\":123} reports still record success.", "POST /api/heartbeat，X-TinyWatch-Heartbeat 填令牌。JSON：{\"event\":\"start\",\"run_id\":\"backup-001\"}；结束时用同一 run_id 报 success 或 fail。旧格式 {\"duration_ms\":123} 仍表示成功。", "POST /api/heartbeat、X-TinyWatch-Heartbeat。{\"event\":\"start\",\"run_id\":\"backup-001\"}。同じ run_id で success または fail。旧形式 {\"duration_ms\":123} は成功。", "POST /api/heartbeat, X-TinyWatch-Heartbeat. {\"event\":\"start\",\"run_id\":\"backup-001\"}, puis success ou fail avec le même run_id. Ancien format {\"duration_ms\":123} = réussite.", "POST /api/heartbeat, X-TinyWatch-Heartbeat. {\"event\":\"start\",\"run_id\":\"backup-001\"}, затем success или fail с тем же run_id. Старый формат {\"duration_ms\":123} означает успех.", "POST /api/heartbeat, X-TinyWatch-Heartbeat. {\"event\":\"start\",\"run_id\":\"backup-001\"}, danach success oder fail mit gleicher run_id. Altes Format {\"duration_ms\":123} meldet Erfolg."],
  runtime_health: ["Monitor health", "监控程序健康", "監視の状態", "État du moniteur", "Состояние монитора", "Monitorzustand"],
  write_failures: ["Write failures", "写盘失败次数", "書き込み失敗", "Échecs d’écriture", "Ошибки записи", "Schreibfehler"],
  queue_age: ["Oldest pending notification", "最早待发通知年龄", "最古の通知", "Âge de notification en attente", "Возраст ожидающего уведомления", "Alter der ältesten Nachricht"],
  pending_notifications: ["Pending notifications", "待发通知", "未送信通知", "Notifications en attente", "Ожидающие уведомления", "Ausstehende Nachrichten"],
  probe_slots: ["Probe slots", "探测槽位", "プローブ枠", "Places de sondage", "Слоты проверок", "Prüfplätze"],
  worker_failed: ["Stopped", "已停止", "停止", "Arrêté", "Остановлен", "Gestoppt"],
  interval_minutes: ["minutes", "分钟", "分", "minutes", "минуты", "Minuten"],

  refresh_services: ["Refresh", "刷新", "更新", "Actualiser", "Обновить", "Aktualisieren"],
  notification_dropped: ["Notification queue was full; this transition was not queued.", "通知队列已满，此次事件未入队。", "通知キューが満杯のため送信を登録できませんでした。", "File de notifications pleine ; événement non enregistré.", "Очередь уведомлений заполнена; событие не добавлено.", "Benachrichtigungswarteschlange voll; Ereignis nicht eingereiht."],

  services: ["Services", "服务监控", "サービス監視", "Services", "Сервисы", "Dienste"],
  service: ["Service availability", "服务可用性", "サービス可用性", "Disponibilité du service", "Доступность сервиса", "Dienstverfügbarkeit"],
  monitors: ["Monitors", "探测项目", "モニター", "Moniteurs", "Мониторы", "Monitore"],
  notifications: ["Notifications", "通知", "通知", "Notifications", "Уведомления", "Benachrichtigungen"],
  maintenance: ["Maintenance windows", "维护窗口", "保守期間", "Périodes de maintenance", "Окна обслуживания", "Wartungsfenster"],
  probe_help: ["Probes run from this console host. The associated asset selects incident context and maintenance scope, not the probe location.", "探测由控制台主机执行；关联资产用于事件归属和维护范围，不代表从该资产发起探测。", "このコンソールから検査します。関連資産はイベントと保守範囲のみを指定します。", "Les sondes partent de cette console. L’actif associé définit les incidents et la maintenance, pas le lieu de sondage.", "Проверки выполняются с узла панели. Связанный узел задаёт контекст и обслуживание, не место проверки.", "Prüfungen laufen auf dem Konsolenhost. Das zugeordnete System bestimmt Vorfälle und Wartung, nicht den Prüfort."],
  add_service: ["Add monitor", "添加探测", "モニター追加", "Ajouter un moniteur", "Добавить монитор", "Monitor hinzufügen"],
  service_limits: ["Up to 24 monitors, intervals 30–3600 seconds. History shows sampled success and mean probe duration in 5-minute buckets over 24h.", "最多 24 项，间隔 30–3600 秒。历史展示 24 小时内的采样成功率和 5 分钟桶的平均探测耗时。", "最大24件、30–3600秒間隔。24時間の成功率と5分平均時間を表示。", "24 moniteurs, intervalles de 30 à 3600 s. Succès échantillonnés et durée moyenne par 5 min sur 24 h.", "До 24 мониторов, интервал 30–3600 с. Успехи и средняя длительность по 5 мин за 24 ч.", "Bis zu 24 Monitore, 30–3600 Sekunden. Stichprobenerfolg und mittlere Dauer je 5 Minuten über 24 h."],
  pending_probe: ["Waiting for probe", "等待探测", "検査待ち", "En attente de sonde", "Ожидание проверки", "Warten auf Prüfung"],
  service_ok: ["Available", "可用", "利用可能", "Disponible", "Доступен", "Verfügbar"],
  service_down: ["Unavailable", "不可用", "利用不可", "Indisponible", "Недоступен", "Nicht verfügbar"],
  associated_asset: ["Associated asset", "关联资产", "関連資産", "Actif associé", "Связанный узел", "Zugeordnetes System"],
  maintenance_active: ["Notifications paused for maintenance", "维护中，通知暂停", "保守中・通知停止", "Notifications suspendues pour maintenance", "Обслуживание: уведомления приостановлены", "Benachrichtigungen wegen Wartung pausiert"],
  sample_success: ["Sample success (24h)", "采样成功率（24h）", "成功率（24時間）", "Succès des sondes (24 h)", "Успешные проверки (24 ч)", "Erfolgreiche Stichproben (24 h)"],
  consecutive_failures: ["Consecutive failures", "连续失败", "連続失敗", "Échecs consécutifs", "Последовательные сбои", "Aufeinanderfolgende Fehler"],
  notification_help: ["Send JSON to a generic webhook on incident trigger/recovery. No redirects. Five attempts, 24h expiry, bounded persistent queue. A receiver should deduplicate event_id; delivery may repeat after a crash.", "告警触发/恢复时发送 JSON 到通用 Webhook，不跟随重定向；最多尝试 5 次，24 小时过期，队列持久化且有上限。接收端应按 event_id 去重，崩溃后可能重复投递。", "発生/復旧時にJSONを送信。リダイレクトなし、5回まで、24時間で期限切れ。event_idで重複を除いてください。", "JSON au déclenchement/rétablissement. Sans redirection, 5 tentatives, expiration 24 h. Dédupliquez event_id après un redémarrage.", "JSON при сбое/восстановлении. Без перенаправлений, 5 попыток, срок 24 ч. Устраняйте дубли по event_id.", "JSON bei Auslösung/Ende. Keine Umleitungen, 5 Versuche, 24 h Ablauf. Empfänger sollten event_id deduplizieren."],
  deliveries: ["Recent deliveries", "最近投递", "最近の配信", "Livraisons récentes", "Последние доставки", "Letzte Zustellungen"],
  maintenance_help: ["Keep collecting and recording incidents while suppressing notifications for selected assets. Still-active incidents notify after maintenance ends; incidents resolved during maintenance remain silent.", "维护期间继续采样和记录事件，仅暂停所选资产的通知。维护结束后仍活跃的事件会通知；维护期间恢复的事件保持静默。", "保守中も収集と記録を継続。終了時に未解決のイベントを通知します。期間中に復旧したものは通知しません。", "Collecte et incidents maintenus sans notifications. Les incidents encore actifs sont signalés à la fin ; ceux résolus restent silencieux.", "Сбор продолжается без уведомлений. Активные инциденты сообщаются после окна; завершённые в окне остаются тихими.", "Erfassung läuft ohne Benachrichtigungen weiter. Noch aktive Vorfälle werden danach gemeldet, während der Wartung beendete bleiben stumm."],
  add_window: ["Add window", "添加窗口", "期間追加", "Ajouter une période", "Добавить окно", "Fenster hinzufügen"],
  service_name: ["Monitor name", "探测名称", "モニター名", "Nom du moniteur", "Название монитора", "Monitorname"],
  protocol: ["Protocol", "协议", "プロトコル", "Protocole", "Протокол", "Protokoll"],
  target: ["URL or TCP host", "URL 或 TCP 主机", "URLまたはTCPホスト", "URL ou hôte TCP", "URL или TCP-узел", "URL oder TCP-Host"],
  expected_status: ["Expected HTTP status", "预期 HTTP 状态码", "期待HTTP状態", "Statut HTTP attendu", "Ожидаемый HTTP-статус", "Erwarteter HTTP-Status"],
  content_match: ["Literal content match (optional, first 64 KiB, UTF-8)", "内容字面匹配（可选，前 64 KiB，UTF-8）", "本文一致（任意、先頭64 KiB、UTF-8）", "Texte à trouver (facultatif, premiers 64 Kio, UTF-8)", "Текст для поиска (до 64 КиБ, UTF-8, необязательно)", "Textabgleich (optional, erste 64 KiB, UTF-8)"],
  interval_seconds: ["Interval (seconds)", "间隔（秒）", "間隔（秒）", "Intervalle (secondes)", "Интервал (секунды)", "Intervall (Sekunden)"],
  failure_threshold: ["Failures before alert", "告警前连续失败次数", "通知までの失敗回数", "Échecs avant alerte", "Сбоев до оповещения", "Fehler bis zum Alarm"],
  service_edit_help: ["Renaming preserves history. Changing the target or matching conditions resets it. One success resolves an incident.", "改名称保留历史，更换目标或匹配条件才重置；一次成功探测即可恢复事件。", "名前変更は履歴を保持。対象や条件の変更はリセット。成功1回で復旧。", "Renommer conserve l’historique. Changer la cible ou les critères le réinitialise. Un succès résout l’incident.", "Переименование сохраняет историю. Смена цели или условий сбрасывает её. Успех закрывает инцидент.", "Umbenennen bewahrt den Verlauf. Ziel- oder Bedingungsänderungen setzen ihn zurück. Ein Erfolg beendet den Vorfall."],
  connection_failed: ["Connection, DNS or TLS failed", "连接、DNS 或 TLS 失败", "接続・DNS・TLS失敗", "Échec de connexion, DNS ou TLS", "Ошибка соединения, DNS или TLS", "Verbindung, DNS oder TLS fehlgeschlagen"],
  unexpected_status: ["Unexpected HTTP status", "HTTP 状态码不符", "HTTP状態が不一致", "Statut HTTP inattendu", "Неожиданный HTTP-статус", "Unerwarteter HTTP-Status"],
  content_mismatch: ["Expected text not found", "未找到预期内容", "期待する本文なし", "Texte attendu absent", "Ожидаемый текст не найден", "Erwarteter Text nicht gefunden"],
  delivery_pending: ["Pending", "待投递", "待機", "En attente", "Ожидает", "Ausstehend"],
  delivery_delivered: ["Delivered", "已投递", "配信済み", "Livré", "Доставлено", "Zugestellt"],
  delivery_failed: ["Delivery failed", "投递失败", "配信失敗", "Échec de livraison", "Ошибка доставки", "Zustellung fehlgeschlagen"],
  delivery_expired: ["Expired", "已过期", "期限切れ", "Expiré", "Истекло", "Abgelaufen"],
  delivery_cancelled: ["Cancelled", "已取消", "中止", "Annulé", "Отменено", "Abgebrochen"],
  timeout_seconds: ["Timeout (seconds)", "超时（秒）", "タイムアウト（秒）", "Délai (secondes)", "Тайм-аут (секунды)", "Zeitlimit (Sekunden)"],

  last_observed: ["Sample time", "采样时间", "サンプル時刻", "Heure de mesure", "Время отсчёта", "Messzeit"],
  cadence: ["Interval", "间隔", "間隔", "Intervalle", "Интервал", "Intervall"],
  collection_time: ["Collection time", "采集耗时", "収集時間", "Durée de collecte", "Время сбора", "Erfassungsdauer"],
  storage_size: ["Database size", "数据库大小", "DBサイズ", "Taille de la base", "Размер базы", "Datenbankgröße"],
  storage_write: ["Last database write", "最近数据库写入耗时", "直近DB書込時間", "Dernière écriture de la base", "Последняя запись базы", "Letzte Datenbankschreibdauer"],

  replay: ["Investigate & replay", "调查与回放", "調査と再生", "Analyse et relecture", "Анализ и воспроизведение", "Untersuchung und Rückblick"],
  partition: ["Partition", "分区", "パーティション", "Partition", "Раздел", "Partition"],
  partition_missing: ["Partition unavailable", "分区暂不可用", "パーティション利用不可", "Partition indisponible", "Раздел недоступен", "Partition nicht verfügbar"],
  aggregate: ["All partitions (aggregate)", "全部分区（汇总）", "全パーティション（合計）", "Toutes les partitions (total)", "Все разделы (суммарно)", "Alle Partitionen (gesamt)"],
  worst_partition: ["Most used partition", "最满分区", "最大使用率のパーティション", "Partition la plus pleine", "Самый заполненный раздел", "Vollste Partition"],
  replay_help: ["Retained samples share one time axis. Gaps and sparse context are observations, not proof of cause.", "保留样本共用时间轴；缺口和稀疏上下文仅为观测，不能证明故障原因。", "保存データを同じ時間軸で表示。欠落と疎な情報は原因の証明ではありません。", "Axe commun aux mesures conservées. Les lacunes et le contexte ne prouvent pas une cause.", "Сохранённые отсчёты на общей оси. Пробелы и контекст не доказывают причину.", "Gemeinsame Zeitachse für gespeicherte Werte. Lücken und Kontext beweisen keine Ursache."],
  from: ["From", "开始时间", "開始", "Début", "Начало", "Von"],
  until: ["Until", "结束时间", "終了", "Fin", "Конец", "Bis"],
  apply: ["Apply range", "应用时间段", "期間を適用", "Appliquer la période", "Применить период", "Zeitraum anwenden"],
  export_report: ["Export offline HTML", "导出离线 HTML", "オフラインHTML出力", "Exporter HTML hors ligne", "Экспорт HTML офлайн", "Offline-HTML exportieren"],
  add_annotation: ["Add annotation", "添加标记", "注釈を追加", "Ajouter une annotation", "Добавить отметку", "Markierung hinzufügen"],
  annotation: ["Annotation", "手动标记", "注釈", "Annotation", "Отметка", "Markierung"],
  annotation_message: ["Description (up to 240 characters)", "说明（最多 240 字）", "説明（240文字以内）", "Description (240 caractères maximum)", "Описание (до 240 символов)", "Beschreibung (bis 240 Zeichen)"],
  system_change: ["System version changed", "系统版本变化", "システム版変更", "Version système modifiée", "Изменение версии системы", "Systemversion geändert"],
  interfaces_change: ["Network interfaces changed", "网卡变化", "ネットワークIF変更", "Interfaces réseau modifiées", "Изменение интерфейсов", "Netzwerkschnittstellen geändert"],
  partitions_change: ["Partitions changed", "分区变化", "パーティション変更", "Partitions modifiées", "Изменение разделов", "Partitionen geändert"],
  reboot: ["Restart observed", "观测到重启", "再起動を検出", "Redémarrage observé", "Обнаружена перезагрузка", "Neustart beobachtet"],
  login_observed: ["Login first observed here", "首次观测到登录记录", "ログインを初観測", "Connexion observée ici", "Впервые обнаруженная запись входа", "Anmeldung erstmals beobachtet"],
  replay_events: ["Changes and annotations", "变化与标记", "変更と注釈", "Modifications et annotations", "Изменения и отметки", "Änderungen und Markierungen"],
  no_events: ["No retained events in this interval.", "该时间段没有保留的事件。", "この期間のイベントはありません。", "Aucun événement conservé sur cette période.", "Нет сохранённых событий за период.", "Keine gespeicherten Ereignisse im Zeitraum."],
  replay_context: ["Nearest retained process snapshot", "最近的保留进程快照", "最も近い保存プロセス情報", "Instantané de processus conservé le plus proche", "Ближайший сохранённый снимок процессов", "Nächstgelegener gespeicherter Prozessstand"],
  context_sampling: ["Top 3 CPU processes only; context may be sparse. Login entries are trigger/snapshot context, not a complete audit log.", "仅保留 CPU 前三进程，上下文可能稀疏；登录条目是快照信息，并非完整审计日志。", "CPU上位3プロセスのみ保存。ログイン情報は完全な監査ログではありません。", "Trois processus CPU seulement ; contexte parfois clairsemé. Les connexions ne forment pas un journal exhaustif.", "Только 3 процесса по CPU; контекст может быть редким. Записи входа не являются полным журналом аудита.", "Nur drei CPU-Spitzenprozesse; Kontext kann lückenhaft sein. Anmeldungen sind kein vollständiges Auditprotokoll."],
  snapshot_age: ["Snapshot distance (seconds)", "快照时间差（秒）", "スナップショットとの差（秒）", "Écart instantané (secondes)", "Расстояние до снимка (секунды)", "Abstand zum Prozessstand (Sekunden)"],
  previous_window: ["Previous window", "上一时间段", "前の期間", "Période précédente", "Предыдущий период", "Vorheriger Zeitraum"],
  next_window: ["Next window", "下一时间段", "次の期間", "Période suivante", "Следующий период", "Nächster Zeitraum"],
  zoom_in: ["Zoom in", "放大", "拡大", "Agrandir", "Увеличить", "Vergrößern"],
  zoom_out: ["Zoom out", "缩小", "縮小", "Réduire", "Уменьшить", "Verkleinern"],
  outside_retention: ["The selected time is outside retained history.", "所选时间超出保留历史范围。", "保存履歴の範囲外です。", "La période dépasse l’historique conservé.", "Период вне сохранённой истории.", "Zeitraum außerhalb des gespeicherten Verlaufs."],
  cursor: ["Inspection time", "检查时间", "確認時刻", "Heure examinée", "Время просмотра", "Untersuchungszeit"],
  sample_resolution: ["Minute samples for 24h; older charts retain extrema at 5-minute/hourly resolution. Sparse context preserves first/last snapshots.", "24 小时内为分钟样本，更早图表按 5 分钟/小时保留极值；上下文稀疏保留首尾快照。", "24時間は毎分、以降は5分/1時間の極値。古い情報は最初と最後のスナップショットです。", "Mesures par minute sur 24 h, puis extrêmes par 5 min/heure. Contexte ancien limité aux premier/dernier instantanés.", "Минутные отсчёты за 24 ч, затем экстремумы за 5 мин/час. Старый контекст: первый/последний снимок.", "Minutenwerte für 24 h, danach Extrema je 5 Minuten/Stunde. Älterer Kontext behält Anfang/Ende."],
  generated: ["Generated", "生成时间", "生成時刻", "Généré", "Создано", "Erstellt"],
  no_credentials: ["This report contains monitoring observations; credentials and dashboard configuration are excluded.", "报告包含监控观测信息，不包含凭证和面板配置。", "レポートには監視情報のみ含み、認証情報や画面設定は含みません。", "Rapport d’observations sans identifiants ni configuration du tableau de bord.", "Отчёт содержит наблюдения, без учётных данных и конфигурации панели.", "Bericht mit Beobachtungen ohne Zugangsdaten und Dashboardkonfiguration."],

  alerts: ['Alerts', '告警', 'アラート', 'Alertes', 'Оповещения', 'Alarme'],
  timeline: ['Incident timeline', '事件时间线', 'インシデント履歴', 'Chronologie des incidents', 'История инцидентов', 'Vorfallverlauf'],
  rules: ['Alert rules', '告警规则', 'アラートルール', 'Règles d’alerte', 'Правила оповещений', 'Alarmregeln'],
  diagnostics: ['Collection diagnostics', '采集诊断', '収集診断', 'Diagnostic de collecte', 'Диагностика сбора', 'Erfassungsdiagnose'],
  fleet: ['Asset health', '资产健康', '資産の状態', 'État des actifs', 'Состояние узлов', 'Zustand der Systeme'],
  healthy: ['Healthy', '正常', '正常', 'Normal', 'В норме', 'Normal'],
  online: ['Online', '在线', 'オンライン', 'En ligne', 'Доступен', 'Online'],
  condition: ['Condition', '触发条件', '条件', 'Condition', 'Условие', 'Bedingung'],
  partial: ['Partial', '部分指标不可用', '一部利用不可', 'Partiel', 'Частичные данные', 'Teilweise verfügbar'],
  stale: ['Stale data', '数据过期', '古いデータ', 'Données anciennes', 'Устаревшие данные', 'Veraltete Daten'],
  offline: ['Offline', '离线', 'オフライン', 'Hors ligne', 'Недоступен', 'Offline'],
  error: ['Collection error', '采集错误', '収集エラー', 'Erreur de collecte', 'Ошибка сбора', 'Erfassungsfehler'],
  unsupported: ['Not exposed by this system', '系统未公开此指标', 'システム非対応', 'Non exposé par le système', 'Система не предоставляет метрику', 'Vom System nicht bereitgestellt'],
  clock_skew: ['Check the node clock', '请检查节点时间', 'ノードの時刻を確認', 'Vérifiez l’horloge du nœud', 'Проверьте часы узла', 'Systemzeit prüfen'],
  active: ['Active', '正在告警', '発生中', 'Actif', 'Активен', 'Aktiv'],
  resolved: ['Resolved', '已恢复', '解決済み', 'Résolu', 'Завершён', 'Beendet'],
  all: ['All', '全部', 'すべて', 'Tous', 'Все', 'Alle'],
  acknowledged: ['Acknowledged', '已确认', '確認済み', 'Acquitté', 'Подтверждён', 'Bestätigt'],
  acknowledge: ['Acknowledge', '确认告警', '確認する', 'Acquitter', 'Подтвердить', 'Bestätigen'],
  no_incidents: ['No incidents in this view.', '当前筛选下没有事件。', '該当するインシデントはありません。', 'Aucun incident pour ce filtre.', 'Нет инцидентов для этого фильтра.', 'Keine Vorfälle für diesen Filter.'],
  no_rules: ['No rules configured.', '尚未配置规则。', 'ルールがありません。', 'Aucune règle configurée.', 'Правила не настроены.', 'Keine Regeln eingerichtet.'],
  add_rule: ['Add rule', '添加规则', 'ルール追加', 'Ajouter une règle', 'Добавить правило', 'Regel hinzufügen'],
  edit: ['Edit', '编辑', '編集', 'Modifier', 'Изменить', 'Bearbeiten'],
  remove: ['Remove', '删除', '削除', 'Supprimer', 'Удалить', 'Entfernen'],
  save: ['Save', '保存', '保存', 'Enregistrer', 'Сохранить', 'Speichern'],
  cancel: ['Cancel', '取消', 'キャンセル', 'Annuler', 'Отмена', 'Abbrechen'],
  close: ['Close', '关闭', '閉じる', 'Fermer', 'Закрыть', 'Schließen'],
  loading: ['Loading…', '正在加载…', '読み込み中…', 'Chargement…', 'Загрузка…', 'Wird geladen…'],
  retry: ['Retry', '重试', '再試行', 'Réessayer', 'Повторить', 'Erneut versuchen'],
  failed: ['Could not save. Check the values and try again.', '保存失败，请检查输入后重试。', '保存できません。入力を確認してください。', 'Échec. Vérifiez les valeurs et réessayez.', 'Не удалось сохранить. Проверьте значения.', 'Speichern fehlgeschlagen. Eingaben prüfen.'],
  saved: ['Saved', '已保存', '保存しました', 'Enregistré', 'Сохранено', 'Gespeichert'],
  name: ['Rule name (optional)', '规则名称（可选）', 'ルール名（任意）', 'Nom de règle (facultatif)', 'Название (необязательно)', 'Regelname (optional)'],
  node: ['Asset', '资产', '資産', 'Actif', 'Узел', 'System'],
  all_nodes: ['All assets, including local', '所有资产（含本机）', 'ローカルを含む全資産', 'Tous les actifs, y compris local', 'Все узлы, включая локальный', 'Alle Systeme, einschließlich lokal'],
  metric: ['Metric', '监控项目', 'メトリック', 'Métrique', 'Метрика', 'Messwert'],
  mode: ['Detection mode', '检测方式', '検出方式', 'Mode de détection', 'Режим обнаружения', 'Erkennungsmodus'],
  threshold: ['Fixed threshold', '固定阈值', '固定しきい値', 'Seuil fixe', 'Фиксированный порог', 'Fester Schwellenwert'],
  baseline: ['Historical baseline', '历史基线', '履歴ベースライン', 'Référence historique', 'Историческая база', 'Historischer Vergleich'],
  trigger: ['Trigger above', '超过此值触发', '超過で発生', 'Déclencher au-dessus de', 'Срабатывание выше', 'Auslösen oberhalb von'],
  recovery: ['Recover at or below', '低于或等于此值恢复', '以下で復旧', 'Rétablir à ou sous', 'Восстановление при или ниже', 'Beenden bei oder unter'],
  minimum_delta: ['Minimum increase above baseline', '相对基线的最小增量', 'ベースラインからの最小増加', 'Hausse minimale sur la référence', 'Минимальный рост над базой', 'Mindestanstieg über Vergleichswert'],
  duration: ['Sustained for (minutes)', '持续时间（分钟）', '継続時間（分）', 'Durée continue (minutes)', 'Длительность (минуты)', 'Dauer (Minuten)'],
  cooldown: ['Cooldown after recovery (minutes)', '恢复后冷却时间（分钟）', '復旧後の待機時間（分）', 'Pause après rétablissement (minutes)', 'Пауза после восстановления (минуты)', 'Pause nach Ende (Minuten)'],
  enabled: ['Enabled', '启用', '有効', 'Activée', 'Включено', 'Aktiviert'],
  disabled: ['Disabled', '停用', '無効', 'Désactivée', 'Выключено', 'Deaktiviert'],
  warming_up: ['Waiting for baseline history', '等待基线历史积累', '履歴データを蓄積中', 'En attente d’historique', 'Ожидание истории', 'Warten auf Verlaufsdaten'],
  unavailable: ['Waiting for valid measurements', '等待有效采样', '有効な測定を待機', 'En attente de mesures valides', 'Ожидание корректных измерений', 'Warten auf gültige Messungen'],
  rule_limit: ['Up to 32 rules.', '最多 32 条规则。', '最大32ルール。', '32 règles maximum.', 'Не более 32 правил.', 'Bis zu 32 Regeln.'],
  sampler_help: ['Evaluated every minute, even with the dashboard closed. Acknowledgement keeps monitoring active.', '每分钟评估一次，关闭网页也会继续。确认告警不会停止监控。', '画面を閉じても毎分評価します。確認後も監視を続けます。', 'Évaluation chaque minute, même sans navigateur. L’acquittement maintient la surveillance.', 'Проверка каждую минуту, даже без браузера. Подтверждение не останавливает мониторинг.', 'Prüfung jede Minute, auch ohne Browser. Bestätigung beendet die Überwachung nicht.'],
  baseline_help: ['Uses the last 24h median and MAD, excluding the latest 10 minutes. Needs 30 samples. Trigger = median + max(minimum increase, 3 × 1.4826 × MAD).', '使用过去 24 小时中位数和 MAD，排除最近 10 分钟，至少需要 30 个样本。触发值 = 中位数 + max(最小增量, 3 × 1.4826 × MAD)。', '直近10分を除く24時間の中央値とMADを使用。30サンプル必要。しきい値 = 中央値 + max(最小増加, 3 × 1.4826 × MAD)。', 'Médiane et MAD sur 24 h, hors les 10 dernières minutes. 30 mesures requises. Seuil = médiane + max(hausse minimale, 3 × 1,4826 × MAD).', 'Медиана и MAD за 24 ч без последних 10 минут. Нужно 30 отсчётов. Порог = медиана + max(минимальный рост, 3 × 1,4826 × MAD).', 'Median und MAD der letzten 24 h ohne letzte 10 Minuten. 30 Werte nötig. Schwelle = Median + max(Mindestanstieg, 3 × 1,4826 × MAD).'],
  baseline_frozen: ['The baseline is frozen during an active incident; it does not adapt to the anomaly.', '告警期间冻结基线，避免持续异常被当作正常。', '発生中は異常に追従しないよう基準を固定します。', 'La référence reste fixe pendant l’incident.', 'База фиксируется на время активного инцидента.', 'Während eines Vorfalls bleibt der Vergleichswert fest.'],
  context: ['Observations at trigger time', '触发时的观测信息', '発生時の観測情報', 'Observations au déclenchement', 'Наблюдения при срабатывании', 'Beobachtungen bei Auslösung'],
  context_help: ['These observations provide context; they do not prove a cause.', '这些信息仅提供上下文，不能证明故障原因。', 'これらは参考情報であり、原因を証明しません。', 'Ces observations donnent du contexte sans prouver une cause.', 'Эти данные дают контекст, но не доказывают причину.', 'Diese Beobachtungen geben Kontext, beweisen aber keine Ursache.'],
  began: ['Started', '开始时间', '開始', 'Début', 'Начало', 'Beginn'],
  triggered: ['Triggered', '触发时间', '発生', 'Déclenchement', 'Срабатывание', 'Ausgelöst'],
  ended: ['Ended', '结束时间', '終了', 'Fin', 'Завершение', 'Ende'],
  current: ['Last observed', '最近观测值', '最新観測値', 'Dernière valeur', 'Последнее значение', 'Letzter Messwert'],
  peak: ['Peak', '峰值', 'ピーク', 'Pic', 'Пик', 'Spitzenwert'],
  median: ['Median', '中位数', '中央値', 'Médiane', 'Медиана', 'Median'],
  samples: ['samples', '样本', 'サンプル', 'mesures', 'отсчётов', 'Messwerte'],
  seconds: ['seconds', '秒', '秒', 'secondes', 'секунд', 'Sekunden'],
  sample_age: ['Sample age', '样本年龄', 'サンプル経過時間', 'Âge de la mesure', 'Возраст измерения', 'Alter des Messwerts'],
  latency: ['Collection latency', '采集耗时', '収集時間', 'Durée de collecte', 'Время сбора', 'Erfassungsdauer'],
  last_success: ['Last successful sample', '最后成功采样', '最終成功サンプル', 'Dernière mesure réussie', 'Последний успешный сбор', 'Letzte erfolgreiche Messung'],
  unavailable_time: ['Unknown', '未知', '不明', 'Inconnu', 'Неизвестно', 'Unbekannt'],
  no_issues: ['No collection issues detected.', '未发现采集问题。', '収集の問題はありません。', 'Aucun problème de collecte détecté.', 'Проблем сбора не обнаружено.', 'Keine Erfassungsprobleme erkannt.'],
  diagnostics_help: ['Healthy: current measurements. Stale: missing timestamp or over 120 seconds old. Partial: unavailable collectors. Node clock differences also affect freshness.', '正常表示数据有效；过期表示无时间戳或超过 120 秒；部分可用表示某些采集器不可用。节点时间差也会影响新鲜度判断。', '正常は新しいデータ、古いデータは時刻なしまたは120秒超、一部利用不可は収集機能の制限。時計差も影響します。', 'Normal : mesures récentes. Ancien : horodatage absent ou plus de 120 s. Partiel : collecteurs indisponibles. Le décalage des horloges peut influer.', 'Норма: свежие данные. Устаревшие: нет времени или старше 120 с. Частичные: недоступные сборщики. Разница часов влияет на оценку.', 'Normal: aktuelle Werte. Veraltet: kein Zeitstempel oder älter als 120 s. Teilweise: nicht verfügbare Erfassung. Zeitunterschiede beeinflussen die Bewertung.'],
  dns_count: ['DNS entries at trigger time', '触发时 DNS 条目数', '発生時のDNS件数', 'Entrées DNS au déclenchement', 'Записи DNS при срабатывании', 'DNS-Einträge bei Auslösung'],
  recovered: ['Measurement recovered', '指标已恢复', 'メトリック復旧', 'Mesure rétablie', 'Метрика восстановилась', 'Messwert wieder normal'],
  rule_changed: ['Rule changed or disabled', '规则已修改或停用', 'ルール変更または無効化', 'Règle modifiée ou désactivée', 'Правило изменено или отключено', 'Regel geändert oder deaktiviert'],
  rule_removed: ['Rule no longer applies', '规则不再适用', 'ルール対象外', 'Règle non applicable', 'Правило больше не применимо', 'Regel nicht mehr anwendbar'],
  asset_removed: ['Asset removed', '资产已移除', '資産削除', 'Actif supprimé', 'Узел удалён', 'System entfernt'],
  http_help: ['Enter IP:port or an HTTP/HTTPS URL, then paste the node token. HTTP sends the token without encryption; use it on a trusted network.', '填写 IP:端口 或 HTTP/HTTPS 地址，再粘贴节点令牌。HTTP 会明文传输令牌，适用于可信网络。', 'IP:ポートまたはHTTP/HTTPS URLとノードトークンを入力。HTTPは暗号化しないため信頼できるネットワークで使用してください。', 'Saisissez IP:port ou une URL HTTP/HTTPS et le jeton du nœud. HTTP transmet le jeton en clair ; utilisez un réseau de confiance.', 'Введите IP:порт или URL HTTP/HTTPS и токен узла. HTTP передаёт токен открыто; используйте доверенную сеть.', 'IP:Port oder HTTP/HTTPS-URL und Systemtoken eingeben. HTTP überträgt den Token unverschlüsselt; für vertrauenswürdige Netzwerke.'],
  history_policy: ['History keeps minute samples for 24h, then first/last/extreme points per 5 minutes through day 7, and per hour afterward. Collection gaps remain visible.', '历史数据保留最近 24 小时的分钟样本；第 2–7 天按 5 分钟保留首尾和极值，更早按小时保留。断采仍会显示。', '24時間は毎分、7日までは5分、以降は1時間ごとの先頭・末尾・極値を保持。収集欠落も表示します。', 'Mesures par minute sur 24 h, puis début/fin/extrêmes par 5 min jusqu’au 7e jour, et par heure ensuite. Les interruptions restent visibles.', 'Отсчёты по минутам за 24 ч, затем первые/последние/экстремальные за 5 мин до 7 дней и за час далее. Пробелы сбора сохраняются.', 'Minutenwerte für 24 h, danach Anfang/Ende/Extrema je 5 Minuten bis Tag 7 und stündlich danach. Erfassungslücken bleiben sichtbar.']
};
function ft(key) {
  const row = FEATURE_MESSAGES[key];
  return row ? row[({en:0,zh:1,ja:2,fr:3,ru:4,de:5})[state.language] ?? 0] : key;
}
function featureDate(timestamp) {
  return timestamp ? new Date(Number(timestamp)*1000).toLocaleString(LANGUAGE_LOCALE[state.language] || 'en-US') : '—';
}
function alertMetricLabel(metric) {
  return metrics[metric] ? tr(metrics[metric][0]) : ft(metric);
}
function alertValue(metric, value) {
  if(value == null || !Number.isFinite(Number(value))) return '—';
  if(metric === 'network') return fmtBytes(value) + '/s';
  if(metric==='service')return ft(Number(value)>0?'service_down':'service_ok');
  if(metric === 'offline') return ft(Number(value) > 0 ? 'offline' : 'online');
  const number = new Intl.NumberFormat(LANGUAGE_LOCALE[state.language] || 'en-US', {maximumFractionDigits:2}).format(value);
  return number + (['cpu','memory','disk'].includes(metric) ? '%' : metric === 'stale' ? ' ' + ft('seconds') : '');
}
function featureHeader(title, helper) {
  return '<header class="modal-head"><div><h3>'+esc(title)+'</h3><p class="helper">'+esc(helper || '')+'</p></div><button type="button" class="close" data-close aria-label="'+esc(ft('close'))+'">×</button></header>';
}
function drawFleetHealth() {
  const target = document.getElementById('fleet-health');
  if(!target) return;
  const reports = state.data?.diagnostics?.nodes || [];
  target.innerHTML = '<div class="fleet-label">'+esc(ft('fleet'))+'</div><div class="fleet-nodes">'+reports.map(node =>
    '<button type="button" class="fleet-node '+esc(node.status)+'" data-diagnostic="'+esc(node.id)+'"><i class="health-dot"></i><span>'+esc(node.name)+'</span><small>'+esc(ft(node.status))+'</small></button>').join('')+'</div>';
  target.querySelectorAll('[data-diagnostic]').forEach(button => button.onclick = () => showDiagnostics(button.dataset.diagnostic));
  const alerts = document.getElementById('alerts-open');
  if(alerts) {
    const count = Number(state.data?.alerts?.active_count) || 0;
    alerts.textContent = ft('alerts') + ' · ' + count;
    alerts.classList.toggle('has-alerts', count > 0);
  }
  if(state.modalKind==='services'&&['monitors','heartbeats'].includes(state.serviceTab)&&!state.serviceEditing&&Date.now()-state.serviceFetchedAt>=10000)loadServices();
  if(state.modalKind === 'diagnostics') updateDiagnostics();
  if(state.modalKind === 'alerts' && state.alertTab === 'incidents' && Date.now()-state.alertFetchedAt >= 60000) loadAlerts();
}
function showDiagnostics(selectedNode) {
  state.diagnosticNode = selectedNode || null;
  modal(featureHeader(ft('diagnostics'), ft('diagnostics_help'))+'<div id="diagnostic-list" class="diagnostic-list"></div>', true);
  state.modalKind = 'diagnostics';
  updateDiagnostics();
}
function updateDiagnostics() {
  const target = document.getElementById('diagnostic-list');
  if(!target) return;
  const reports = [...(state.data?.diagnostics?.nodes || [])];
  reports.sort((left,right) => Number(right.id === state.diagnosticNode)-Number(left.id === state.diagnosticNode));
  const storage=state.data?.diagnostics?.storage;
  const runtime=state.data?.diagnostics?.runtime;
  const health=runtime?'<article class="diagnostic-card"><strong>'+esc(ft('runtime_health'))+'</strong><p class="helper">'+esc(ft('last_success'))+': '+esc(featureDate(runtime.last_persisted_at))+' · '+esc(ft('write_failures'))+': '+runtime.write_failures+'</p><p class="helper">'+esc(ft('pending_notifications'))+': '+runtime.notification_pending+' · '+esc(ft('queue_age'))+': '+runtime.notification_oldest_seconds+' s · '+esc(ft('storage_size'))+': '+esc(fmtBytes(runtime.history_bytes))+'</p>'+Object.entries(runtime.workers).map(([name,worker])=>'<p class="helper"><span class="tag '+(!worker.running||worker.failed||worker.stale||worker.probes_overdue||worker.requests_overdue?'bad':'good')+'">'+esc(ft('worker_'+name))+' · '+esc(ft(worker.restarting?'worker_restarting':!worker.running||worker.failed?'worker_failed':worker.stale||worker.probes_overdue||worker.requests_overdue?'stale':'healthy'))+'</span> · '+worker.age_seconds+' s · '+esc(ft('worker_restarts'))+' '+(worker.restarts||0)+(worker.last_error?' · '+esc(worker.last_error):'')+(worker.probe_slots_limit?' · '+esc(ft('probe_slots'))+' '+worker.probe_slots_used+'/'+worker.probe_slots_limit+' · '+worker.oldest_probe_seconds+' s':'')+(worker.requests_limit?' · '+worker.requests_used+'/'+worker.requests_limit+' · '+worker.requests_oldest_seconds+' s':'')+'</p>').join('')+'</article>':'';
  target.innerHTML = health+(storage?'<p class="helper">'+esc(ft('storage_size'))+': '+esc(fmtBytes(storage.bytes))+' · '+esc(ft('storage_write'))+': '+esc(storage.last_write_ms??'—')+' ms · '+esc(ft('encoded_days'))+': '+esc(storage.encoded_days??'—')+'</p>':'')+reports.map(node => {
    const stamp = node.last_success_at ? new Date(node.last_success_at).toLocaleString(LANGUAGE_LOCALE[state.language] || 'en-US') : ft('unavailable_time');
    const age = node.age_seconds == null ? ft('unavailable_time') : Math.round(node.age_seconds)+' '+ft('seconds');
    return '<article class="diagnostic-card"><div class="feature-card-head"><strong>'+esc(node.name)+'</strong><span class="health-status '+esc(node.status)+'">'+esc(ft(node.status))+'</span></div><dl class="feature-facts"><div><dt>'+esc(ft('last_success'))+'</dt><dd>'+esc(stamp)+'</dd></div><div><dt>'+esc(ft('sample_age'))+'</dt><dd>'+esc(age)+'</dd></div><div><dt>'+esc(ft('latency'))+'</dt><dd>'+(node.latency_ms == null ? '—' : esc(node.latency_ms)+' ms')+'</dd></div></dl>'+
      Object.entries(node.collectors||{}).map(([name,status])=>'<p class="helper">'+esc(alertMetricLabel(name))+': '+esc(featureDate(status.sampled_at))+' · '+esc(ft('cadence'))+' '+esc(status.interval_seconds)+' '+esc(ft('seconds'))+' · '+esc(ft('collection_time'))+' '+esc(status.duration_ms)+' ms</p>').join('')+
      (node.error ? '<p class="asset-error">'+esc(node.error)+'</p>' : '')+
      (node.next_retry_at?'<p class="helper">'+esc(ft('next_retry'))+': '+esc(featureDate(node.next_retry_at))+' · '+esc(ft('consecutive_failures'))+': '+node.consecutive_failures+'</p>':'')+
      (node.issues.length ? '<ul class="diagnostic-issues">'+node.issues.map(issue => '<li><strong>'+esc(alertMetricLabel(issue.metric))+'</strong> · '+esc(ft(issue.kind))+(issue.message ? '<p>'+esc(issue.message)+'</p>' : '')+'</li>').join('')+'</ul>' : (node.status === 'healthy' ? '<p class="helper">'+esc(ft('no_issues'))+'</p>' : ''))+'</article>';
  }).join('');
}
async function showAlerts(tab) {
  state.alertTab = tab || 'incidents';
  modal(featureHeader(ft('alerts'), ft('sampler_help'))+'<div id="alert-panel"><p class="helper">'+esc(ft('loading'))+'</p></div>', true);
  state.modalKind = 'alerts';
  await loadAlerts();
}
async function loadAlerts() {
  if(state.alertLoading) return;
  const request = ++state.alertRequest;
  state.alertLoading = request;
  try {
    const data = await api('/api/alerts');
    if(request !== state.alertRequest || state.modalKind !== 'alerts') return;
    state.alertData = data; state.alertFetchedAt = Date.now();
    renderAlertPanel();
  } catch(error) {
    const target = document.getElementById('alert-panel');
    if(target && state.modalKind === 'alerts') {
      target.innerHTML = '<p class="asset-error">'+esc(tr(error.message))+'</p><button type="button" class="button" id="alert-retry">'+esc(ft('retry'))+'</button>';
      document.getElementById('alert-retry').onclick = loadAlerts;
    }
  } finally { if(state.alertLoading === request) state.alertLoading = false; }
}
function incidentCard(item) {
  const title = item.rule_name || alertMetricLabel(item.metric);
  const baseline = item.baseline;
  const context = item.context || {};
  const processRows = (context.processes || []).map(process => '<tr><td>'+esc(process.name)+'</td><td>'+esc(process.pid)+'</td><td>'+esc(alertValue('cpu', process.cpu))+'</td><td>'+esc(fmtBytes(process.memory))+'</td></tr>').join('');
  const observations = (processRows ? '<div class="table-scroll"><table class="data-table"><thead><tr><th>'+esc(tr('进程'))+'</th><th>PID</th><th>CPU</th><th>'+esc(tr('内存'))+'</th></tr></thead><tbody>'+processRows+'</tbody></table></div>' : '')+
    (context.probe_error?'<p class="asset-error">'+esc(ft(context.probe_error))+'</p>':'')+
    (context.logins || []).map(entry => '<p class="context-log"><b>'+esc(entry.kind)+'</b> '+esc(entry.message)+'</p>').join('')+
    '<p class="helper">'+esc(ft('dns_count'))+': '+esc(context.dns?.count ?? 0)+'</p>'+
    (context.connection_error ? '<p class="asset-error">'+esc(context.connection_error)+'</p>' : '')+
    Object.entries(context.collector_errors || {}).map(([metric,error]) => '<p class="asset-error">'+esc(alertMetricLabel(metric))+': '+esc(error)+'</p>').join('');
  const baselineInfo = baseline ? '<p class="baseline-evidence">'+esc(ft('median'))+': '+esc(alertValue(item.metric,baseline.median))+' · MAD: '+esc(alertValue(item.metric,baseline.mad))+' · '+baseline.samples+' '+esc(ft('samples'))+'</p><p class="helper">'+esc(ft('baseline_help'))+' '+esc(ft('baseline_frozen'))+'</p>' : '';
  return '<article class="incident '+esc(item.status)+'"><div class="feature-card-head"><div><strong>'+esc(title)+'</strong><div class="metric-sub">'+esc(item.node_name)+' · '+esc(item.partition_mount||'')+' '+esc(alertMetricLabel(item.metric))+' · '+esc(ft(item.mode))+'</div></div><span class="health-status '+(item.status === 'active' ? 'offline' : 'healthy')+'">'+esc(ft(item.status))+'</span></div>'+
    '<dl class="feature-facts"><div><dt>'+esc(ft('triggered'))+'</dt><dd>'+esc(featureDate(item.triggered_at))+'</dd></div><div><dt>'+esc(ft(item.metric === 'offline' ? 'condition' : 'trigger'))+'</dt><dd>'+esc(item.metric === 'offline' ? ft('offline') : alertValue(item.metric,item.threshold))+'</dd></div><div><dt>'+esc(ft('current'))+'</dt><dd>'+esc(alertValue(item.metric,item.last_value))+'<small>'+esc(featureDate(item.last_observed_at))+'</small></dd></div><div><dt>'+esc(ft('peak'))+'</dt><dd>'+esc(alertValue(item.metric,item.peak))+'</dd></div></dl>'+
    '<details><summary>'+esc(ft('context'))+'</summary><p class="helper">'+esc(ft('began'))+': '+esc(featureDate(item.started_at))+' · '+esc(ft('recovery'))+': '+esc(alertValue(item.metric,item.recovery))+'</p>'+baselineInfo+observations+'<p class="helper">'+esc(ft('context_help'))+'</p></details>'+
    (item.status === 'resolved' ? '<p class="helper">'+esc(ft('ended'))+': '+esc(featureDate(item.resolved_at))+' · '+esc(ft(item.resolution_reason || 'recovered'))+'</p>' : '')+
    (item.notification_dropped?'<p class="asset-error">'+esc(ft('notification_dropped'))+'</p>':'')+
    (item.status==='active'&&item.notification_suppressed?'<p class="helper">'+esc(ft('maintenance_active'))+'</p>':'')+
    '<div class="incident-actions">'+((state.alertData?.flight_ids||[]).includes(item.id)?'<button type="button" class="button subtle" data-flight="'+esc(item.id)+'">'+esc(ft('flight_record'))+'</button>':'')+'<button type="button" class="button subtle" data-replay="'+esc(item.id)+'">'+esc(ft('replay'))+'</button>'+(item.acknowledged_at ? '<span class="helper">'+esc(ft('acknowledged'))+' · '+esc(featureDate(item.acknowledged_at))+'</span>' : '<button type="button" class="button subtle" data-ack="'+esc(item.id)+'">'+esc(ft('acknowledge'))+'</button>')+'</div></article>';
}
function renderAlertPanel() {
  const target = document.getElementById('alert-panel'), data = state.alertData;
  if(!target || !data) return;
  const tabs = '<div class="feature-tabs" role="tablist">'+['incidents','rules'].map(tab => '<button type="button" role="tab" aria-selected="'+(state.alertTab === tab)+'" class="button '+(state.alertTab === tab ? 'primary' : 'subtle')+'" data-alert-tab="'+tab+'">'+esc(ft(tab === 'incidents' ? 'timeline' : 'rules'))+'</button>').join('')+'</div>';
  if(state.alertTab === 'incidents') {
    const assets = [{id:'*',name:ft('all_nodes')},{id:'local',name:nodeFor('local')?.name || 'Local'}].concat(state.config.assets || []);
    for(const item of data.incidents)if(!assets.some(asset => asset.id === item.node))assets.push({id:item.node,name:item.node_name});
    const items = data.incidents.filter(item => (state.alertStatus === 'all' || item.status === state.alertStatus) && (state.alertNode === '*' || item.node === state.alertNode));
    target.innerHTML = tabs+'<div class="feature-toolbar"><select id="incident-status" class="select-mini" aria-label="'+esc(ft('alerts'))+'">'+['all','active','resolved'].map(status => '<option value="'+status+'" '+(state.alertStatus === status ? 'selected' : '')+'>'+esc(ft(status))+'</option>').join('')+'</select><select id="incident-node" class="select-mini" aria-label="'+esc(ft('node'))+'">'+assets.map(asset => '<option value="'+esc(asset.id)+'" '+(state.alertNode === asset.id ? 'selected' : '')+'>'+esc(asset.name)+'</option>').join('')+'</select><span class="helper">'+esc(ft('active'))+': '+data.active_count+'</span></div><div class="incident-list">'+(items.length ? items.map(incidentCard).join('') : '<div class="empty">'+esc(ft('no_incidents'))+'</div>')+'</div>';
    document.getElementById('incident-status').onchange = event => {state.alertStatus = event.target.value;renderAlertPanel()};
    document.getElementById('incident-node').onchange = event => {state.alertNode = event.target.value;renderAlertPanel()};
    target.querySelectorAll('[data-ack]').forEach(button => button.onclick = async () => {
      button.disabled = true;
      try {
        state.alertData = await api('/api/alerts','POST',{action:'ack',id:button.dataset.ack});
        if(state.modalKind === 'alerts') renderAlertPanel();
        await refresh();
      } catch(error) {button.disabled = false;toast(ft('failed'))}
    });
  } else {
    const rows = data.rules.map(rule => {
      const asset = rule.node === '*' ? ft('all_nodes') : nodeFor(rule.node)?.name || state.config.assets.find(asset => asset.id === rule.node)?.name || rule.node;
      const ruleStates = Object.entries(data.states || {}).filter(([key]) => key.startsWith(rule.id+':')).map(([,value]) => value.evaluation);
      const waiting = ruleStates.includes('warming_up') ? 'warming_up' : ruleStates.includes('unavailable') ? 'unavailable' : '';
      return '<article class="rule-card"><div class="feature-card-head"><div><strong>'+esc(rule.name || alertMetricLabel(rule.metric))+'</strong><div class="metric-sub">'+esc(asset)+' · '+esc(ft(rule.mode))+'</div></div><span class="tag '+(rule.enabled ? 'good' : '')+'">'+esc(ft(rule.enabled ? 'enabled' : 'disabled'))+'</span></div><p class="helper">'+esc(ft(rule.metric === 'offline' ? 'condition' : rule.mode === 'baseline' ? 'minimum_delta' : 'trigger'))+': '+esc(rule.metric === 'offline' ? ft('offline') : alertValue(rule.metric,rule.threshold))+' · '+esc(ft('duration'))+': '+rule.duration/60+'</p>'+(rule.enabled && waiting ? '<p class="helper">'+esc(ft(waiting))+'</p>' : '')+'<div class="rule-actions"><button type="button" class="button subtle" data-edit-rule="'+esc(rule.id)+'">'+esc(ft('edit'))+'</button><button type="button" class="button danger" data-remove-rule="'+esc(rule.id)+'">'+esc(ft('remove'))+'</button></div></article>';
    }).join('');
    target.innerHTML = tabs+'<div class="feature-toolbar"><button type="button" class="button primary" id="add-alert-rule" '+(data.rules.length >= 32 ? 'disabled' : '')+'>'+esc(ft('add_rule'))+'</button><span class="helper">'+esc(ft('rule_limit'))+'</span></div><div id="rule-editor"></div><div class="rule-list">'+(rows || '<div class="empty">'+esc(ft('no_rules'))+'</div>')+'</div>';
    document.getElementById('add-alert-rule').onclick = () => editAlertRule();
    target.querySelectorAll('[data-edit-rule]').forEach(button => button.onclick = () => editAlertRule(data.rules.find(rule => rule.id === button.dataset.editRule)));
    target.querySelectorAll('[data-remove-rule]').forEach(button => button.onclick = async () => {
      button.disabled = true;
      try {
        state.alertData = await api('/api/alerts','POST',{action:'save_rules',rules:data.rules.filter(rule => rule.id !== button.dataset.removeRule)});
        if(state.modalKind === 'alerts') renderAlertPanel();
        await refresh();
      } catch(error) {button.disabled = false;toast(ft('failed'))}
    });
  }
  target.querySelectorAll('[data-flight]').forEach(button=>button.onclick=()=>showFlight(button.dataset.flight));
  target.querySelectorAll('[data-replay]').forEach(button=>button.onclick=()=>{const item=data.incidents.find(entry=>entry.id===button.dataset.replay);if(item)showReplay(item.node,item.triggered_at,item.partition!=='*'?item.partition:'')});
  target.querySelectorAll('[data-alert-tab]').forEach(button => button.onclick = () => {state.alertTab = button.dataset.alertTab;renderAlertPanel()});
}
function editAlertRule(existing) {
  const rule = existing || {id:'r-'+(crypto.randomUUID ? crypto.randomUUID() : Date.now()),name:'',node:'*',metric:'cpu',mode:'threshold',threshold:90,recovery:85,duration:180,cooldown:300,enabled:true};
  const assets = [{id:'*',name:ft('all_nodes')},{id:'local',name:nodeFor('local')?.name || 'Local'}].concat(state.config.assets || []);
  const target = document.getElementById('rule-editor');
  const previewEnd=new Date(),previewStart=new Date(Date.now()-Math.min(7,state.config.history_retention_days||7)*86400000+60000);
  target.innerHTML = '<form id="alert-rule-form" class="rule-editor"><div class="form-grid"><div class="field full"><label for="rule-name">'+esc(ft('name'))+'</label><input id="rule-name" maxlength="80" value="'+esc(rule.name)+'"></div><div class="field"><label for="rule-node">'+esc(ft('node'))+'</label><select id="rule-node">'+assets.map(asset => '<option value="'+esc(asset.id)+'" '+(rule.node === asset.id ? 'selected' : '')+'>'+esc(asset.name)+'</option>').join('')+'</select></div><div class="field"><label for="rule-metric">'+esc(ft('metric'))+'</label><select id="rule-metric">'+['cpu','memory','disk','network','load','offline','stale'].map(metric => '<option value="'+metric+'" '+(rule.metric === metric ? 'selected' : '')+'>'+esc(alertMetricLabel(metric))+'</option>').join('')+'</select></div><div class="field full" id="rule-partition-field"><label for="rule-partition">'+esc(ft('partition'))+'</label><select id="rule-partition"></select></div><div class="field full"><label for="rule-mode">'+esc(ft('mode'))+'</label><select id="rule-mode">'+['threshold','baseline'].map(mode => '<option value="'+mode+'" '+(rule.mode === mode ? 'selected' : '')+'>'+esc(ft(mode))+'</option>').join('')+'</select></div><div class="field" id="rule-threshold-field"><label for="rule-threshold" id="rule-threshold-label"></label><input id="rule-threshold" type="number" min="0" step="any" required value="'+rule.threshold+'"></div><div class="field" id="rule-recovery-field"><label for="rule-recovery">'+esc(ft('recovery'))+'</label><input id="rule-recovery" type="number" min="0" step="any" required value="'+rule.recovery+'"></div><div class="field"><label for="rule-duration">'+esc(ft('duration'))+'</label><input id="rule-duration" type="number" min="0" max="1440" step="any" required value="'+rule.duration/60+'"></div><div class="field"><label for="rule-cooldown">'+esc(ft('cooldown'))+'</label><input id="rule-cooldown" type="number" min="0" max="10080" step="any" required value="'+rule.cooldown/60+'"></div><div class="field full"><label class="checkbox-label"><input id="rule-enabled" type="checkbox" '+(rule.enabled ? 'checked' : '')+'>'+esc(ft('enabled'))+'</label></div></div><p class="helper hidden" id="rule-baseline-help">'+esc(ft('baseline_help'))+'</p><div class="form-grid"><div class="field"><label for="rule-preview-start">'+esc(ft('from'))+'</label><input type="datetime-local" id="rule-preview-start" value="'+localDateTimeValue(previewStart)+'"></div><div class="field"><label for="rule-preview-end">'+esc(ft('until'))+'</label><input type="datetime-local" id="rule-preview-end" value="'+localDateTimeValue(previewEnd)+'"></div></div><p class="helper">'+esc(ft('preview_help'))+'</p><button type="button" class="button subtle" id="rule-preview">'+esc(ft('preview_rule'))+'</button><div id="rule-preview-result" aria-live="polite"></div><p class="error-message" id="rule-error" role="alert"></p><div class="modal-actions"><button type="button" class="button subtle" id="rule-cancel">'+esc(ft('cancel'))+'</button><button type="submit" class="button primary">'+esc(ft('save'))+'</button></div></form>';
  const mode = document.getElementById('rule-mode'), metric = document.getElementById('rule-metric');
  function updatePartitions(){
    const node=document.getElementById('rule-node').value,select=document.getElementById('rule-partition');
    const previous=select.value||rule.partition||'*',parts=nodeFor(node)?.metrics?.disk?.partitions||[];
    select.innerHTML='<option value="*">'+esc(ft('worst_partition'))+'</option>'+parts.filter(part=>part.id).map(part=>'<option value="'+esc(part.id)+'">'+esc(part.mount)+'</option>').join('');
    if(node!=='*'&&previous!=='*'&&!parts.some(part=>part.id===previous))select.insertAdjacentHTML('beforeend','<option value="'+esc(previous)+'">'+esc(ft('partition_missing'))+'</option>');
    select.value=node==='*'?'*':previous;
    document.getElementById('rule-partition-field').classList.toggle('hidden',metric.value!=='disk');
  }
  document.getElementById('rule-node').onchange=updatePartitions;
  function updateFields(reset) {
    updatePartitions();
    const availability = ['offline','stale'].includes(metric.value), offline = metric.value === 'offline';
    if(availability) mode.value = 'threshold';
    mode.disabled = availability;
    const baseline = mode.value === 'baseline';
    document.getElementById('rule-threshold-field').classList.toggle('hidden',offline);
    document.getElementById('rule-recovery-field').classList.toggle('hidden',offline || baseline);
    document.getElementById('rule-baseline-help').classList.toggle('hidden',!baseline);
    document.getElementById('rule-threshold-label').textContent = ft(baseline ? 'minimum_delta' : 'trigger') + (metric.value === 'network' ? ' (B/s)' : ['cpu','memory','disk'].includes(metric.value) ? ' (%)' : '');
    if(offline) {document.getElementById('rule-threshold').value = 0;document.getElementById('rule-recovery').value = 0}
    else if(reset) {
      document.getElementById('rule-threshold').value = metric.value === 'stale' ? 120 : baseline ? 10 : metric.value === 'load' ? 4 : metric.value === 'network' ? 10485760 : 90;
      document.getElementById('rule-recovery').value = metric.value === 'stale' ? 60 : metric.value === 'load' ? 2 : metric.value === 'network' ? 5242880 : 85;
    }
  }
  mode.onchange = () => updateFields(true); metric.onchange = () => updateFields(true); updateFields(false);
  document.getElementById('rule-cancel').onclick = () => {target.innerHTML = ''};
  document.getElementById('rule-name').focus({preventScroll:true});
  function readRule(){
    return {id:rule.id,name:document.getElementById('rule-name').value,node:document.getElementById('rule-node').value,metric:metric.value,partition:metric.value==='disk'?document.getElementById('rule-partition').value:'*',mode:mode.value,threshold:Number(document.getElementById('rule-threshold').value),recovery:mode.value === 'baseline' ? 0 : Number(document.getElementById('rule-recovery').value),duration:Math.round(Number(document.getElementById('rule-duration').value)*60),cooldown:Math.round(Number(document.getElementById('rule-cooldown').value)*60),enabled:document.getElementById('rule-enabled').checked};
  }
  let previewGeneration=0;
  const form=document.getElementById('alert-rule-form'),previewButton=document.getElementById('rule-preview'),previewResult=document.getElementById('rule-preview-result');
  form.addEventListener('input',()=>{previewGeneration++;previewResult.replaceChildren()});
  previewButton.onclick=async()=>{
    if(!form.reportValidity())return;
    const generation=++previewGeneration;previewButton.disabled=true;
    try{
      const result=await api('/api/alerts/preview','POST',{rule:readRule(),start:new Date(document.getElementById('rule-preview-start').value).getTime()/1000,end:new Date(document.getElementById('rule-preview-end').value).getTime()/1000});
      if(!previewResult.isConnected||generation!==previewGeneration)return;
      previewResult.innerHTML='<p class="helper">'+esc(ft('preview_count'))+': '+result.count+(result.enabled?'':' · '+esc(ft('disabled')))+'</p>'+result.reports.map(report=>{
        const coverage=Math.min(100,report.known_seconds/(result.end-result.start)*100);
        return '<article class="diagnostic-card"><strong>'+esc(nodeFor(report.node)?.name||report.node)+'</strong><p class="helper">'+esc(ft('preview_coverage'))+': '+coverage.toFixed(1)+'% · '+esc(ft('preview_count'))+': '+report.count+'</p>'+report.events.map(event=>'<p class="helper">'+esc(featureDate(event.triggered_at))+' → '+esc(event.resolved_at?featureDate(event.resolved_at):ft('active'))+' · '+esc(ft('preview_observed'))+': '+Math.round(event.observed_seconds/60)+' '+esc(ft('interval_minutes'))+(event.uncertain?' · '+esc(ft('preview_uncertain')):'')+'</p>').join('')+report.unknown_ranges.slice(0,10).map(range=>'<p class="helper">'+esc(ft('preview_unknown'))+': '+esc(featureDate(range[0]))+' — '+esc(featureDate(range[1]))+'</p>').join('')+'</article>';
      }).join('');
    }catch(error){if(previewResult.isConnected&&generation===previewGeneration)previewResult.textContent=tr(error.message)}
    finally{if(previewButton.isConnected)previewButton.disabled=['offline','stale'].includes(metric.value)}
  };
  previewButton.disabled=['offline','stale'].includes(metric.value);
  metric.addEventListener('change',()=>{previewButton.disabled=['offline','stale'].includes(metric.value)});
  document.getElementById('alert-rule-form').onsubmit = async event => {
    event.preventDefault();
    const next = readRule();
    const rules = state.alertData.rules.filter(item => item.id !== rule.id).concat(next);
    const submit = event.target.querySelector('[type=submit]'); submit.disabled = true;
    try {
      state.alertData = await api('/api/alerts','POST',{action:'save_rules',rules});
      if(state.modalKind === 'alerts') renderAlertPanel();
      toast(ft('saved')); await refresh();
    } catch(error) {const field = document.getElementById('rule-error');if(field)field.textContent = ft('failed');submit.disabled = false}
  };
}
// Replay reads retained samples; it does not refresh agents.
function replaySamples(result,metric){
  const index={cpu:1,memory:3,disk:3,load:1};
  return (result.points||[]).map((point,i)=>({timestamp:Number(point[0]),
    value:metric==='network'?Number(point[1])+Number(point[2]):Number(point[index[metric]]),
    rx:metric==='network'?Number(point[1]):undefined,tx:metric==='network'?Number(point[2]):undefined,
    gapBefore:Boolean((result.gaps||[])[i])})).filter(point=>Number.isFinite(point.timestamp)&&Number.isFinite(point.value));
}
function replayEventList(data){
  return data.events.concat(data.incidents.flatMap(item=>[
    {id:item.id,node:item.node,timestamp:item.triggered_at,kind:'alerts',message:(item.rule_name||alertMetricLabel(item.metric))+' · '+ft('active')},
    ...(item.resolved_at?[{id:item.id+'-resolved',timestamp:item.resolved_at,kind:'alerts',message:(item.rule_name||alertMetricLabel(item.metric))+' · '+ft('resolved')}]:[])
  ])).filter(item=>item.timestamp>=data.start&&item.timestamp<=data.end).sort((a,b)=>a.timestamp-b.timestamp);
}
function jobRunsHTML(runs){
  const rows=runs.slice().reverse();
  return '<details><summary>'+esc(ft('run_history'))+'</summary><div class="table-scroll"><table class="data-table"><thead><tr><th>Run ID</th><th>'+esc(ft('run_result'))+'</th><th>'+esc(ft('from'))+'</th><th>'+esc(ft('until'))+'</th><th>'+esc(ft('run_duration'))+'</th></tr></thead><tbody>'+rows.map(run=>
    '<tr><td>'+esc(run.id)+'</td><td>'+esc(ft('run_'+run.status))+(run.overlap?'<p class="helper">'+esc(ft('overlapping'))+'</p>':'')+(run.timed_out_at&&run.status!=='timeout'?'<p class="helper">'+esc(ft('late_completion'))+'</p>':'')+(run.message?'<p class="helper">'+esc(run.message)+'</p>':'')+'</td><td>'+esc(featureDate(run.started_at))+'</td><td>'+esc(featureDate(run.finished_at))+'</td><td>'+esc(run.duration_ms??'—')+'</td></tr>'
  ).join('')+'</tbody></table></div></details>';
}
async function showComparison(node,center){
  modal(featureHeader(ft('comparison'),ft('comparison_help'))+
    '<form id="comparison-form"><div class="form-grid"><div class="field"><label for="comparison-center">'+esc(ft('change_time'))+'</label><input id="comparison-center" type="datetime-local" required value="'+localDateTimeValue(new Date(center*1000))+'"></div><div class="field"><label for="comparison-span">'+esc(ft('window_minutes'))+'</label><select id="comparison-span"><option value="300">5</option><option value="1800" selected>30</option><option value="7200">120</option></select></div></div><div class="modal-actions"><button class="button primary" type="submit">'+esc(ft('apply'))+'</button></div></form><div id="comparison-result"></div>',true);
  state.modalKind='comparison';
  const comparison=state.comparison={node,center,span:1800,request:0};
  document.getElementById('comparison-form').onsubmit=event=>{
    event.preventDefault();
    comparison.center=new Date(document.getElementById('comparison-center').value).getTime()/1000;
    comparison.span=Number(document.getElementById('comparison-span').value);
    loadComparison(comparison);
  };
  await loadComparison(comparison);
}
async function loadComparison(comparison){
  const target=document.getElementById('comparison-result'),request=++comparison.request;
  if(!target)return;
  target.innerHTML='<p class="helper">'+esc(ft('loading'))+'</p>';
  try{
    const query=new URLSearchParams({node:comparison.node,center:comparison.center,span:comparison.span});
    const data=await api('/api/comparison?'+query);
    if(state.modalKind!=='comparison'||state.comparison!==comparison||request!==comparison.request)return;
    const before=data.windows.before,after=data.windows.after;
    function summary(metric,value){
      return esc(alertValue(metric,value.median))+' / '+esc(alertValue(metric,value.peak))+' / '+value.coverage+'%';
    }
    const rows=Object.keys(before.resources).map(metric=>{
      const change=data.changes[metric];
      const delta=change.median_delta;
      return '<tr><td>'+esc(alertMetricLabel(metric))+'</td><td>'+summary(metric,before.resources[metric])+'</td><td>'+summary(metric,after.resources[metric])+'</td><td>'+(delta==null?'—':(delta<0?'−':delta>0?'+':'')+esc(['cpu','memory','disk'].includes(metric)?new Intl.NumberFormat(LANGUAGE_LOCALE[state.language]||'en-US',{maximumFractionDigits:2}).format(Math.abs(delta))+' '+ft('percentage_points'):alertValue(metric,Math.abs(delta))))+(!change.sufficient?'<p class="helper">'+esc(ft('low_coverage'))+'</p>':'')+'</td></tr>';
    }).join('');
    const serviceRows=before.services.map(left=>{
      const right=after.services.find(item=>item.id===left.id);
      return '<tr><td>'+esc(left.name)+'</td><td>'+esc(left.mean_ms??'—')+' ms / '+left.failures+' / '+left.coverage+'%</td><td>'+esc(right?.mean_ms??'—')+' ms / '+(right?.failures??0)+' / '+(right?.coverage??0)+'%</td></tr>';
    }).join('');
    target.innerHTML='<p class="helper">'+esc(featureDate(before.start))+' — '+esc(featureDate(before.end))+' · '+esc(featureDate(after.start))+' — '+esc(featureDate(after.end))+'</p>'+
      '<p class="helper">'+esc(ft('sample_median'))+' / '+esc(ft('peak_value'))+' / '+esc(ft('coverage'))+'</p><div class="table-scroll"><table class="data-table"><thead><tr><th>'+esc(ft('metric'))+'</th><th>'+esc(ft('before'))+'</th><th>'+esc(ft('after'))+'</th><th>'+esc(ft('change_delta'))+'</th></tr></thead><tbody>'+rows+'</tbody></table></div>'+
      '<h4>'+esc(ft('services'))+'</h4><p class="helper">'+esc(ft('latency'))+' / '+esc(ft('sample_failures'))+' / '+esc(ft('coverage'))+'</p><div class="table-scroll"><table class="data-table"><thead><tr><th>'+esc(ft('service_name'))+'</th><th>'+esc(ft('before'))+'</th><th>'+esc(ft('after'))+'</th></tr></thead><tbody>'+serviceRows+'</tbody></table></div>'+
      '<div class="duo">'+[['before',before],['after',after]].map(([side,window])=>'<div class="duo-box"><strong>'+esc(ft(side))+'</strong><p>'+esc(ft('new_incidents'))+': '+window.triggered.length+'</p><p>'+esc(ft('resolved_incidents'))+': '+window.resolved.length+'</p><p>'+esc(ft('active'))+': '+window.active_at_end.length+'</p></div>').join('')+'</div>';
  }catch(error){
    if(state.modalKind==='comparison'&&state.comparison===comparison&&request===comparison.request)target.innerHTML='<p class="asset-error">'+esc(tr(error.message))+'</p>';
  }
}
async function showFlight(id){
  modal(featureHeader(ft('flight_record'),ft('flight_help'))+'<div id="flight-panel"></div>',true);
  state.modalKind='flight';
  const flight=state.flight={id,request:0};
  await loadFlight(flight);
}
async function loadFlight(flight){
  const target=document.getElementById('flight-panel'),request=++flight.request;
  if(!target)return;
  target.innerHTML='<p class="helper">'+esc(ft('loading'))+'</p>';
  try{
    const data=await api('/api/flight?incident='+encodeURIComponent(flight.id));
    if(state.modalKind!=='flight'||state.flight!==flight||request!==flight.request)return;
    const charts=['cpu','memory','disk','network','load'].map(metric=>{
      const points=data.points.filter(point=>Number.isFinite(point.values[metric]));
      const samples=points.map((point,index)=>({timestamp:point.timestamp,value:point.values[metric],gapBefore:index>0&&point.timestamp-points[index-1].timestamp>5}));
      return '<section class="replay-chart"><h4>'+esc(alertMetricLabel(metric))+(metric==='disk'?' · '+esc(ft('worst_partition')):'')+'</h4>'+sparkline(samples,metric,data)+'</section>';
    }).join('');
    target.innerHTML='<div class="feature-toolbar"><span class="tag">'+esc(ft(data.status))+'</span><span>'+esc(ft('coverage'))+': '+data.coverage+'%</span><button type="button" class="button subtle" id="flight-refresh">'+esc(ft('refresh_services'))+'</button></div><p class="helper">'+esc(featureDate(data.start))+' — '+esc(featureDate(data.end))+'</p><div class="replay-charts">'+charts+'</div><div class="field"><label for="flight-cursor">'+esc(ft('cursor'))+'</label><input id="flight-cursor" type="range" min="0" max="'+Math.max(0,data.points.length-1)+'" value="0" '+(!data.points.length?'disabled':'')+'></div><div id="flight-context"></div>';
    document.getElementById('flight-refresh').onclick=()=>loadFlight(flight);
    const slider=document.getElementById('flight-cursor');
    function select(index){
      const point=data.points[index],context=document.getElementById('flight-context');
      if(!point){context.innerHTML='<p class="helper">'+esc(ft('unavailable'))+'</p>';return}
      slider.value=String(index);
      context.innerHTML='<p class="helper">'+esc(featureDate(point.timestamp))+'</p>'+replayContextHTML([point.timestamp,{processes:point.processes,collector_status:{processes:{sampled_at:point.process_sample_at}}}],point.timestamp)+
        (point.errors.length?'<p class="helper">'+esc(ft('error'))+': '+esc(point.errors.join(', '))+'</p>':'');
      for(const chart of target.querySelectorAll('.mini-chart')){
        let line=chart.querySelector('.replay-marker');
        if(!line){line=document.createElementNS('http://www.w3.org/2000/svg','line');line.setAttribute('class','replay-marker');chart.appendChild(line)}
        const x=74+(point.timestamp-data.start)/(data.end-data.start)*240;
        for(const [key,value] of Object.entries({x1:x,x2:x,y1:9,y2:101}))line.setAttribute(key,String(value));
      }
    }
    slider.oninput=()=>select(Number(slider.value));
    target.querySelectorAll('.mini-chart').forEach(chart=>{
      bindChartTooltip(chart);
      chart.addEventListener('click',event=>{
        if(!data.points.length)return;
        const rect=chart.getBoundingClientRect(),ratio=Math.max(0,Math.min(1,((event.clientX-rect.left)*320/rect.width-74)/240));
        const stamp=data.start+ratio*(data.end-data.start);
        let closest=0;
        data.points.forEach((point,index)=>{if(Math.abs(point.timestamp-stamp)<Math.abs(data.points[closest].timestamp-stamp))closest=index});
        select(closest);
      });
    });
    select(Math.max(0,data.points.findIndex(point=>point.timestamp>=data.triggered_at)));
  }catch(error){
    if(state.modalKind==='flight'&&state.flight===flight&&request===flight.request)target.innerHTML='<p class="asset-error">'+esc(tr(error.message))+'</p>';
  }
}
async function showReplay(node='local',center,partition=''){
  const now=Math.floor(Date.now()/1000),cutoff=now-(Number(state.config.history_retention_days)||7)*86400;
  center=Number.isFinite(Number(center))?Number(center):now-900;
  if(center+900<cutoff){toast(ft('outside_retention'));return}
  const window={node,partition,start:Math.max(cutoff+60,center-900),end:Math.min(now,center+900)};
  if(window.start>=window.end){toast(ft('outside_retention'));return}
  modal(featureHeader(ft('replay'),ft('replay_help'))+'<div id="replay-panel"></div>',true);
  state.modalKind='replay';state.replay={window,data:null,cursor:center};
  await loadReplay();
}
async function loadReplay(){
  const replay=state.replay;if(!replay||state.modalKind!=='replay')return;
  state.replayController?.abort();const controller=new AbortController();state.replayController=controller;
  const request=++state.replayRequest,query=new URLSearchParams(replay.window);
  const target=document.getElementById('replay-panel');if(!target)return;
  target.innerHTML='<p class="helper">'+esc(ft('loading'))+'</p>';
  try{
    const data=await api('/api/investigation?'+query,'GET',undefined,controller.signal);
    if(request!==state.replayRequest||state.modalKind!=='replay'||state.replay!==replay)return;
    replay.data=data;replay.window.end=data.end;replay.cursor=Math.max(data.start,Math.min(data.end,replay.cursor));renderReplay();
  }catch(error){
    if(error.name==='AbortError'||request!==state.replayRequest||state.modalKind!=='replay')return;
    target.innerHTML='<p class="asset-error">'+esc(tr(error.message))+'</p><button type="button" class="button" id="replay-retry">'+esc(ft('retry'))+'</button>';
    document.getElementById('replay-retry').onclick=loadReplay;
  }
}
function renderReplay(){
  const replay=state.replay,data=replay?.data,target=document.getElementById('replay-panel');if(!data||!target)return;
  const assets=[{id:'local',name:nodeFor('local')?.name||'Local'}].concat(state.config.assets||[]);
  if(!assets.some(asset=>asset.id===data.node))assets.push({id:data.node,name:data.name});
  const charts=Object.entries(data.charts).map(([metric,result])=>'<section class="replay-chart" data-replay-metric="'+metric+'"><h4>'+esc(alertMetricLabel(metric))+(metric==='disk'&&replay.window.partition?' · '+esc(ft('partition')):'')+'</h4><div class="metric-sub replay-readout">—</div>'+sparkline(replaySamples(result,metric),metric,data)+'</section>').join('');
  const events=replayEventList(data);
  const eventHTML=events.map(item=>'<article class="replay-event '+esc(item.kind)+'">'+
    (item.kind==='annotation'?'<button type="button" class="button subtle" data-remove-annotation="'+esc(item.id)+'">'+esc(ft('remove'))+'</button>':'')+
    '<button type="button" class="button subtle" data-event-time="'+item.timestamp+'">'+esc(featureDate(item.timestamp))+'</button><strong>'+esc(ft(item.kind))+'</strong><p>'+esc(item.message)+'</p></article>').join('');
  target.innerHTML='<form id="replay-range-form"><div class="form-grid"><div class="field"><label for="replay-node">'+esc(ft('node'))+'</label><select id="replay-node">'+assets.map(asset=>'<option value="'+esc(asset.id)+'" '+(data.node===asset.id?'selected':'')+'>'+esc(asset.name)+'</option>').join('')+'</select></div><div class="field"><label for="replay-partition">'+esc(ft('partition'))+'</label><select id="replay-partition"></select></div><div class="field"><label for="replay-start">'+esc(ft('from'))+'</label><input type="datetime-local" id="replay-start" required value="'+localDateTimeValue(new Date(data.start*1000))+'"></div><div class="field"><label for="replay-end">'+esc(ft('until'))+'</label><input type="datetime-local" id="replay-end" required value="'+localDateTimeValue(new Date(data.end*1000))+'"></div></div><div class="replay-toolbar"><button type="submit" class="button primary">'+esc(ft('apply'))+'</button><button type="button" class="button subtle" id="replay-compare">'+esc(ft('compare_change'))+'</button><button type="button" class="button subtle" id="replay-export">'+esc(ft('export_report'))+'</button></div></form>'+
    '<div class="replay-window-controls">'+[['previous_window','←'],['next_window','→'],['zoom_in','＋'],['zoom_out','−']].map(([key,icon])=>'<button type="button" class="button subtle" data-replay-window="'+key+'" aria-label="'+esc(ft(key))+'" title="'+esc(ft(key))+'">'+icon+'</button>').join('')+'</div>'+
    '<p class="helper">'+esc(ft('sample_resolution'))+'</p><label for="replay-cursor" class="helper">'+esc(ft('cursor'))+'</label><input type="range" id="replay-cursor" min="'+data.start+'" max="'+data.end+'" step="1" value="'+replay.cursor+'" style="width:100%"><p id="replay-cursor-label" class="helper"></p><div class="replay-charts">'+charts+'</div>'+
    '<h4>'+esc(ft('replay_context'))+'</h4><div id="replay-context" class="replay-context"></div><p class="helper">'+esc(ft('context_sampling'))+'</p>'+
    '<h4>'+esc(ft('replay_events'))+'</h4><div class="replay-events">'+(eventHTML||'<p class="helper">'+esc(ft('no_events'))+'</p>')+'</div>'+
    '<form id="annotation-form"><div class="form-grid"><div class="field"><label for="annotation-time">'+esc(ft('cursor'))+'</label><input id="annotation-time" type="datetime-local" required value="'+localDateTimeValue(new Date(replay.cursor*1000))+'"></div><div class="field"><label for="annotation-message">'+esc(ft('annotation_message'))+'</label><input id="annotation-message" maxlength="240" required autocomplete="off"></div></div><p id="annotation-error" class="error-message" role="alert"></p><div class="modal-actions"><button type="submit" class="button primary">'+esc(ft('add_annotation'))+'</button></div></form>';
  document.getElementById('replay-compare').onclick=()=>showComparison(data.node,replay.cursor);
  const nodeSelect=document.getElementById('replay-node'),partitionSelect=document.getElementById('replay-partition');
  function populatePartitions(){
    const parts=nodeFor(nodeSelect.value)?.metrics?.disk?.partitions||[],selected=nodeSelect.value===data.node?replay.window.partition:'';
    partitionSelect.innerHTML='<option value="">'+esc(ft('aggregate'))+'</option>'+parts.filter(part=>part.id).map(part=>'<option value="'+esc(part.id)+'" '+(part.id===selected?'selected':'')+'>'+esc(part.mount)+'</option>').join('');
    if(selected&&!parts.some(part=>part.id===selected))partitionSelect.insertAdjacentHTML('beforeend','<option selected value="'+esc(selected)+'">'+esc(ft('partition_missing'))+'</option>');
  }
  populatePartitions();nodeSelect.onchange=populatePartitions;
  document.getElementById('replay-range-form').onsubmit=event=>{event.preventDefault();replay.window={node:nodeSelect.value,partition:partitionSelect.value,start:new Date(document.getElementById('replay-start').value).getTime()/1000,end:new Date(document.getElementById('replay-end').value).getTime()/1000};loadReplay()};
  target.querySelectorAll('[data-replay-window]').forEach(button=>button.onclick=()=>{
    const span=data.end-data.start,kind=button.dataset.replayWindow,center=replay.cursor||((data.start+data.end)/2);
    let start=data.start,end=data.end;
    if(kind==='previous_window'){start-=span;end-=span}
    if(kind==='next_window'){start+=span;end+=span}
    if(kind==='zoom_in'){start=center-Math.max(120,span/4);end=center+Math.max(120,span/4)}
    if(kind==='zoom_out'){start=center-span;end=center+span}
    const now=Date.now()/1000,cutoff=now-(Number(state.config.history_retention_days)||7)*86400+60;
    start=Math.max(start,cutoff);end=Math.min(end,now);
    if(start>=end){toast(ft('outside_retention'));return}
    replay.window={...replay.window,start,end};loadReplay();
  });
  target.querySelectorAll('.mini-chart').forEach(bindChartTooltip);
  target.querySelectorAll('[data-event-time]').forEach(button=>button.onclick=()=>syncReplayCursor(Number(button.dataset.eventTime)));
  document.getElementById('replay-cursor').oninput=event=>syncReplayCursor(Number(event.target.value));
  document.getElementById('replay-export').onclick=exportReplayReport;
  document.getElementById('annotation-form').onsubmit=async event=>{
    event.preventDefault();const button=event.target.querySelector('[type=submit]');button.disabled=true;
    try{
      await api('/api/annotations','POST',{node:data.node,timestamp:new Date(document.getElementById('annotation-time').value).getTime()/1000,message:document.getElementById('annotation-message').value});
      if(state.modalKind==='replay'&&state.replay===replay)await loadReplay();
    }catch(error){const errorField=document.getElementById('annotation-error');if(errorField&&state.replay===replay)errorField.textContent=tr(error.message);button.disabled=false}
  };
  target.querySelectorAll('[data-remove-annotation]').forEach(button=>button.onclick=async()=>{
    button.disabled=true;
    try{await api('/api/annotations','POST',{action:'remove',id:button.dataset.removeAnnotation});if(state.replay===replay&&state.modalKind==='replay')await loadReplay()}
    catch(error){button.disabled=false;toast(error.message)}
  });
  // Use the shared time window for event markers, including sparse charts.
  for(const chart of target.querySelectorAll('.mini-chart')){
    const stride=Math.max(1,Math.ceil(events.length/200));
    for(const item of events.filter((event,index)=>index%stride===0)){
      const x=74+(item.timestamp-data.start)/(data.end-data.start)*240;
      const line=document.createElementNS('http://www.w3.org/2000/svg','line');
      for(const [key,value] of Object.entries({class:'replay-marker',x1:x,x2:x,y1:9,y2:101}))line.setAttribute(key,String(value));
      chart.appendChild(line);
    }
  }
  syncReplayCursor(replay.cursor);
}
function replayContextHTML(row,cursor){
  if(!row)return '<p class="helper">'+esc(ft('unavailable'))+'</p>';
  const context=row[1],processes=context.processes||[];
  const processStamp=Number(context.collector_status?.processes?.sampled_at)||row[0];
  return '<p class="helper">'+esc(featureDate(processStamp))+' · '+esc(ft('snapshot_age'))+': '+Math.round(Math.abs(processStamp-cursor))+'</p><div class="table-scroll"><table class="data-table"><thead><tr><th>'+esc(tr('进程'))+'</th><th>PID</th><th>CPU</th><th>'+esc(tr('内存'))+'</th></tr></thead><tbody>'+processes.map(item=>'<tr><td>'+esc(item.name)+'</td><td>'+esc(item.pid)+'</td><td>'+esc(alertValue('cpu',item.cpu))+'</td><td>'+esc(fmtBytes(item.memory))+'</td></tr>').join('')+'</tbody></table></div>'+
    (context.logins||[]).map(item=>'<p class="helper">'+esc(item.kind)+': '+esc(item.message)+'</p>').join('')+
    Object.entries(context.capabilities||{}).map(([metric,available])=>'<p class="helper">'+esc(alertMetricLabel(metric))+': '+esc(ft(available?'healthy':'unavailable'))+'</p>').join('')+
    Object.entries(context.collector_status||{}).map(([metric,status])=>'<p class="helper">'+esc(alertMetricLabel(metric))+': '+esc(featureDate(status.sampled_at))+' · '+esc(ft('cadence'))+' '+esc(status.interval_seconds)+' '+esc(ft('seconds'))+'</p>').join('')+
    Object.entries(context.collector_errors||{}).map(([metric,error])=>'<p class="asset-error">'+esc(alertMetricLabel(metric))+': '+esc(error)+'</p>').join('');
}
function syncReplayCursor(timestamp){
  const replay=state.replay,data=replay?.data;if(!data||state.modalKind!=='replay')return;
  timestamp=Math.max(data.start,Math.min(data.end,timestamp));replay.cursor=timestamp;
  const target=document.getElementById('replay-panel');if(!target)return;
  document.getElementById('replay-cursor').value=String(timestamp);
  document.getElementById('replay-cursor-label').textContent=ft('cursor')+': '+featureDate(timestamp);
  for(const card of target.querySelectorAll('[data-replay-metric]')){
    const metric=card.dataset.replayMetric,samples=replaySamples(data.charts[metric],metric);
    const nearest=samples.reduce((best,item)=>!best||Math.abs(item.timestamp-timestamp)<Math.abs(best.timestamp-timestamp)?item:best,null);
    card.querySelector('.replay-readout').textContent=nearest?alertValue(metric,nearest.value)+' · '+featureDate(nearest.timestamp)+' · Δ '+Math.round(Math.abs(nearest.timestamp-timestamp))+' '+ft('seconds'):'—';
    const line=card.querySelector('.chart-crosshair'),x=74+(timestamp-data.start)/(data.end-data.start)*240;
    if(line){line.setAttribute('x1',String(x));line.setAttribute('x2',String(x))}
  }
  const nearest=data.observations.reduce((best,row)=>!best||Math.abs(row[0]-timestamp)<Math.abs(best[0]-timestamp)?row:best,null);
  document.getElementById('replay-context').innerHTML=replayContextHTML(nearest,timestamp);
  // Do not overwrite the annotation form while the user is typing.
  const time=document.getElementById('annotation-time');if(!document.getElementById('annotation-message').value&&document.activeElement!==time)time.value=localDateTimeValue(new Date(timestamp*1000));
}
function exportReplayReport(){
  const data=state.replay?.data;if(!data||state.modalKind!=='replay')return;
  const sections=Array.from(document.querySelectorAll('#replay-panel .replay-chart')).map(card=>{
    const metric=card.dataset.replayMetric,clone=card.cloneNode(true);
    clone.querySelectorAll('[data-chart-id]').forEach(chart=>{chart.removeAttribute('data-chart-id');chart.removeAttribute('tabindex')});
    clone.querySelectorAll('.chart-crosshair,.chart-hover').forEach(item=>item.remove());
    // Exact retained values are available offline as well as the SVG preview.
    const rows=data.charts[metric].points.map(point=>'<tr><td>'+esc(featureDate(point[0]))+'</td><td>'+esc(point.slice(1).join(' / '))+'</td></tr>').join('');
    return clone.outerHTML+'<details><summary>'+esc(ft('samples'))+' · '+data.charts[metric].points.length+'</summary><table class="data-table"><tbody>'+rows+'</tbody></table></details>';
  }).join('');
  const events=replayEventList(data).map(item=>'<p><time>'+esc(featureDate(item.timestamp))+'</time> · <strong>'+esc(ft(item.kind))+'</strong> · '+esc(item.message)+'</p>').join('');
  const contexts=data.observations.map(row=>'<details><summary>'+esc(featureDate(row[0]))+'</summary>'+replayContextHTML(row,row[0])+'</details>').join('');
  const incidents=document.createElement('div');incidents.innerHTML=data.incidents.map(incidentCard).join('');
  incidents.querySelectorAll('button').forEach(button=>button.remove());
  const css=Array.from(document.querySelectorAll('style')).map(style=>style.textContent).join('\n');
  const html='<!doctype html><html lang="'+esc(state.language)+'" data-theme="'+esc(state.config.theme)+'"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;"><title>TinyWatch · '+esc(ft('replay'))+'</title><style>'+css+'\nbody{padding:24px;max-width:1100px;margin:auto}.replay-chart{margin-top:12px}details{margin:10px 0}time{font-variant-numeric:tabular-nums}</style></head><body><h1>TinyWatch · '+esc(ft('replay'))+'</h1><h2>'+esc(data.name)+'</h2><p>'+esc(featureDate(data.start))+' — '+esc(featureDate(data.end))+'</p><p class="helper">'+esc(ft('generated'))+': '+esc(featureDate(data.generated_at))+'</p><p>'+esc(ft('no_credentials'))+'</p><p>'+esc(ft('replay_help'))+'</p><p class="helper">'+esc(ft('sample_resolution'))+'</p>'+sections+'<h2>'+esc(ft('alerts'))+'</h2>'+incidents.innerHTML+'<h2>'+esc(ft('replay_events'))+'</h2>'+(events||esc(ft('no_events')))+'<h2>'+esc(ft('replay_context'))+'</h2><p>'+esc(ft('context_sampling'))+'</p>'+contexts+'</body></html>';
  const url=URL.createObjectURL(new Blob([html],{type:'text/html;charset=utf-8'})),link=document.createElement('a');
  link.href=url;link.download='tinywatch-report-'+data.generated_at+'.html';document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}

// Service settings have their own endpoint and revision number.
async function showServices(tab='monitors'){
  state.serviceTab=tab;state.serviceEditing=false;state.serviceData=null;
  modal(featureHeader(ft('services'),ft('probe_help'))+'<div id="service-panel"><p class="helper">'+esc(ft('loading'))+'</p></div>',true);
  state.modalKind='services';await loadServices();
}
async function loadServices(){
  if(state.serviceLoading)return;
  const request=++state.serviceRequest;state.serviceLoading=request;
  try{
    const data=await api('/api/services');
    if(state.modalKind!=='services'||request!==state.serviceRequest)return;
    state.serviceData=data;state.serviceFetchedAt=Date.now();renderServices();
  }catch(error){if(state.modalKind==='services'&&request===state.serviceRequest){const target=document.getElementById('service-panel');if(target&&!state.serviceData){target.innerHTML='<p class="asset-error">'+esc(tr(error.message))+'</p><button type="button" class="button" id="service-retry">'+esc(ft('retry'))+'</button>';document.getElementById('service-retry').onclick=loadServices}else toast(error.message)}}
  finally{if(state.serviceLoading===request)state.serviceLoading=false}
}
function serviceAssets(all=false){
  return (all?[{id:'*',name:ft('all_nodes')}]:[]).concat([{id:'local',name:nodeFor('local')?.name||'Local'}],state.config.assets||[]);
}
async function saveServices(payload){
  if(state.serviceSaving)return;
  state.serviceSaving=true;const request=++state.serviceRequest;
  try{
    const data=await api('/api/services','POST',{...payload,revision:state.serviceData.revision});
    if(request===state.serviceRequest&&state.modalKind==='services'){state.serviceData=data;state.serviceEditing=false;renderServices()}
    toast(ft('saved'));
  }finally{state.serviceSaving=false}
}
function serviceStatus(service,result){
  if(!service.enabled)return ft('disabled');
  if(!result)return ft('pending_probe');
  if(Date.now()/1000-result.sampled_at>service.interval*2+service.timeout)return ft('stale');
  return ft(result.ok?'service_ok':'service_down');
}
function renderServices(){
  const target=document.getElementById('service-panel'),data=state.serviceData;if(!target||!data)return;
  const tabs='<div class="feature-tabs"><button type="button" class="button subtle" id="service-refresh">'+esc(ft('refresh_services'))+'</button>'+['monitors','heartbeats','notifications','maintenance'].map(tab=>'<button type="button" class="button '+(tab===state.serviceTab?'primary':'subtle')+'" data-service-tab="'+tab+'">'+esc(ft(tab))+'</button>').join('')+'</div>';
  let content='';
  if(state.serviceTab==='heartbeats'){
    content='<p class="helper">'+esc(ft('heartbeat_help'))+'</p>'+data.heartbeats.map(job=>{
      const result=data.states[job.id],runs=data.runs?.[job.id]||[];
      return '<article class="diagnostic-card"><div class="feature-card-head"><strong>'+esc(job.name)+'</strong><span class="tag '+(result?.active_id?'bad':'good')+'">'+esc(ft(result?.active_id?'service_down':runs.some(run=>run.status==='running')?'run_running':job.last_success_at?'service_ok':'pending_probe'))+'</span></div><p class="helper">'+esc(ft('last_success'))+': '+esc(featureDate(job.last_success_at))+' · '+esc(ft('cadence'))+': '+job.interval/60+' '+esc(ft('interval_minutes'))+'</p>'+jobRunsHTML(runs)+(result?.error?'<p class="asset-error">'+esc(ft(result.error))+'</p>':'')+'<div class="field"><label>'+esc(ft('heartbeat_token'))+'</label><input readonly aria-label="'+esc(ft('heartbeat_token'))+'" value="'+esc(job.token)+'"></div><div class="modal-actions"><button type="button" class="button" data-edit-job="'+esc(job.id)+'">'+esc(ft('edit'))+'</button><button type="button" class="button danger" data-remove-job="'+esc(job.id)+'">'+esc(ft('remove'))+'</button></div></article>';
    }).join('')+'<p class="helper">'+esc(ft('heartbeat_endpoint'))+'</p><form id="heartbeat-form"><input id="heartbeat-id" type="hidden"><div class="form-grid"><div class="field"><label for="heartbeat-name">'+esc(ft('service_name'))+'</label><input id="heartbeat-name" required maxlength="80"></div><div class="field"><label for="heartbeat-node">'+esc(ft('node'))+'</label><select id="heartbeat-node">'+serviceAssets().map(asset=>'<option value="'+esc(asset.id)+'">'+esc(asset.name)+'</option>').join('')+'</select></div><div class="field"><label for="heartbeat-interval">'+esc(ft('heartbeat_interval'))+'</label><input id="heartbeat-interval" type="number" min="1" max="43200" required value="1440"></div><div class="field"><label for="heartbeat-runtime">'+esc(ft('max_runtime'))+'</label><input id="heartbeat-runtime" type="number" min="1" max="10080" required value="60"></div><div class="field"><label for="heartbeat-grace">'+esc(ft('heartbeat_grace'))+'</label><input id="heartbeat-grace" type="number" min="0" max="10080" required value="10"></div></div><p id="service-error" class="error-message" role="alert"></p><div class="modal-actions"><button class="button primary" type="submit">'+esc(ft('save'))+'</button></div></form>';
  }else if(state.serviceTab==='monitors'){
    content='<div class="feature-toolbar"><button type="button" class="button primary" id="add-service" '+(data.services.length>=24?'disabled':'')+'>'+esc(ft('add_service'))+'</button><span class="helper">'+esc(ft('service_limits'))+'</span></div><div id="service-editor"></div><div class="service-grid">'+data.services.map(service=>{
      const result=data.states[service.id],buckets=data.history[service.id]||[];
      const samples=buckets.reduce((sum,bucket)=>sum+bucket.samples,0),successes=buckets.reduce((sum,bucket)=>sum+bucket.successes,0);
      const history=buckets.map((bucket,index)=>({timestamp:bucket.last_at,value:bucket.sum_ms/bucket.samples,
        gapBefore:index>0&&bucket.first_at-buckets[index-1].last_at>service.interval*2+service.timeout}));
      const maintenance=data.maintenance.some(window=>data.active_maintenance.includes(window.id)&&['*',service.node].includes(window.node));
      return '<article class="diagnostic-card"><div class="feature-card-head"><strong>'+esc(service.name)+'</strong><span class="tag '+(result?.ok?'good':'bad')+'">'+esc(serviceStatus(service,result))+'</span></div><p class="helper">'+esc(service.protocol.toUpperCase())+' · '+esc(service.target)+(service.protocol!=='http'?':'+service.port:'')+'</p><p class="helper">'+esc(ft('associated_asset'))+': '+esc(serviceAssets().find(asset=>asset.id===service.node)?.name||service.node)+(maintenance?' · '+esc(ft('maintenance_active')):'')+'</p><div class="duo"><div class="duo-box"><label>'+esc(ft('latency'))+'</label><strong>'+(result?esc(result.latency_ms)+' ms':'—')+'</strong></div><div class="duo-box"><label>'+esc(ft('sample_success'))+'</label><strong>'+(samples?(successes/samples*100).toFixed(1)+'%':'—')+'</strong></div></div>'+sparkline(history,'latency')+'<p class="helper">'+esc(ft('last_observed'))+': '+esc(featureDate(result?.sampled_at))+' · '+esc(ft('cadence'))+': '+service.interval+' '+esc(ft('seconds'))+'</p>'+
        (result&&!result.ok?'<p class="asset-error">'+esc(ft(result.error))+(result.status_code?' · HTTP '+result.status_code:'')+' · '+esc(ft('consecutive_failures'))+': '+result.failed_count+'</p>':'')+
        (service.protocol==='tls'?'<p class="helper">'+esc(ft('certificate_until'))+': '+esc(featureDate(result?.certificate_expires_at))+' · '+esc(ft('days_remaining'))+': '+esc(result?.certificate_days_remaining??'—')+'</p>':'')+
        '<div class="replay-toolbar"><button type="button" class="button subtle" data-edit-service="'+esc(service.id)+'">'+esc(ft('edit'))+'</button><button type="button" class="button danger" data-remove-service="'+esc(service.id)+'">'+esc(ft('remove'))+'</button></div></article>';
    }).join('')+'</div>';
  }else if(state.serviceTab==='notifications'){
    const config=data.notifications;
    content='<p class="helper">'+esc(ft('notification_help'))+'</p><form id="notification-form"><div class="field"><label for="notification-url">Webhook URL</label><input id="notification-url" type="url" maxlength="1024" value="'+esc(config.url)+'" placeholder="https://example.com/webhook"></div><label class="checkbox-label"><input id="notification-enabled" type="checkbox" '+(config.enabled?'checked':'')+'>'+esc(ft('enabled'))+'</label><p id="service-error" class="error-message" role="alert"></p><div class="modal-actions"><button type="submit" class="button primary">'+esc(ft('save'))+'</button></div></form><h4>'+esc(ft('deliveries'))+'</h4>'+data.deliveries.map(job=>'<div class="disk-line"><span>'+esc(featureDate(job.created_at))+'<div class="metric-sub">'+esc(job.id)+'</div></span><span>'+esc(ft('delivery_'+job.status))+' · '+job.attempts+'/5'+(job.error?' · '+esc(ft(job.error)):'')+'</span></div>').join('');
  }else{
    content='<p class="helper">'+esc(ft('maintenance_help'))+'</p>'+data.maintenance.map(window=>'<article class="replay-event"><strong>'+esc(window.name||ft('maintenance'))+'</strong> · '+esc(serviceAssets(true).find(asset=>asset.id===window.node)?.name||window.node)+'<p>'+esc(featureDate(window.start))+' — '+esc(featureDate(window.end))+'</p>'+(data.active_maintenance.includes(window.id)?'<span class="tag">'+esc(ft('maintenance_active'))+'</span>':'')+'<button type="button" class="button danger" data-remove-maintenance="'+esc(window.id)+'">'+esc(ft('remove'))+'</button></article>').join('')+
      '<form id="maintenance-form"><div class="form-grid"><div class="field"><label for="maintenance-name">'+esc(ft('annotation_message'))+'</label><input id="maintenance-name" maxlength="80"></div><div class="field"><label for="maintenance-node">'+esc(ft('node'))+'</label><select id="maintenance-node">'+serviceAssets(true).map(asset=>'<option value="'+esc(asset.id)+'">'+esc(asset.name)+'</option>').join('')+'</select></div><div class="field"><label for="maintenance-start">'+esc(ft('from'))+'</label><input id="maintenance-start" type="datetime-local" required value="'+localDateTimeValue(new Date())+'"></div><div class="field"><label for="maintenance-end">'+esc(ft('until'))+'</label><input id="maintenance-end" type="datetime-local" required value="'+localDateTimeValue(new Date(Date.now()+3600000))+'"></div></div><p id="service-error" class="error-message" role="alert"></p><div class="modal-actions"><button type="submit" class="button primary">'+esc(ft('add_window'))+'</button></div></form>';
  }
  target.innerHTML=tabs+content;
  document.getElementById('service-refresh').onclick=loadServices;
  target.querySelectorAll('[data-service-tab]').forEach(button=>button.onclick=()=>{state.serviceTab=button.dataset.serviceTab;state.serviceEditing=false;renderServices()});
  target.querySelectorAll('.mini-chart').forEach(bindChartTooltip);
  if(state.serviceTab==='monitors'){
    document.getElementById('add-service').onclick=()=>editService();
    target.querySelectorAll('[data-edit-service]').forEach(button=>button.onclick=()=>editService(data.services.find(service=>service.id===button.dataset.editService)));
    target.querySelectorAll('[data-remove-service]').forEach(button=>button.onclick=async()=>{button.disabled=true;try{await saveServices({action:'services',services:data.services.filter(service=>service.id!==button.dataset.removeService)})}catch(error){button.disabled=false;toast(error.message)}});
  }
  const heartbeatForm=document.getElementById('heartbeat-form');
  if(heartbeatForm){
    heartbeatForm.oninput=()=>{state.serviceEditing=true};
    target.querySelectorAll('input[readonly]').forEach(input=>input.onclick=()=>input.select());
    target.querySelectorAll('[data-edit-job]').forEach(button=>button.onclick=()=>{
      const job=data.heartbeats.find(item=>item.id===button.dataset.editJob);
      document.getElementById('heartbeat-id').value=job.id;document.getElementById('heartbeat-name').value=job.name;
      document.getElementById('heartbeat-node').value=job.node;document.getElementById('heartbeat-interval').value=job.interval/60;
      document.getElementById('heartbeat-grace').value=job.grace/60;document.getElementById('heartbeat-runtime').value=(job.max_runtime||3600)/60;state.serviceEditing=true;
      document.getElementById('heartbeat-name').focus();
    });
    target.querySelectorAll('[data-remove-job]').forEach(button=>button.onclick=async()=>{button.disabled=true;try{await saveServices({action:'heartbeats',heartbeats:data.heartbeats.filter(job=>job.id!==button.dataset.removeJob)})}catch(error){button.disabled=false;toast(error.message)}});
    heartbeatForm.onsubmit=event=>{
      const id=document.getElementById('heartbeat-id').value||'job-'+(crypto.randomUUID?crypto.randomUUID():Date.now());
      const job={id,name:document.getElementById('heartbeat-name').value,node:document.getElementById('heartbeat-node').value,interval:Number(document.getElementById('heartbeat-interval').value)*60,grace:Number(document.getElementById('heartbeat-grace').value)*60,max_runtime:Number(document.getElementById('heartbeat-runtime').value)*60};
      submitServiceForm(event,{action:'heartbeats',heartbeats:data.heartbeats.filter(item=>item.id!==id).concat(job)});
    };
  }
  const notificationForm=document.getElementById('notification-form');
  if(notificationForm)notificationForm.onsubmit=event=>submitServiceForm(event,{action:'notifications',url:document.getElementById('notification-url').value,enabled:document.getElementById('notification-enabled').checked});
  const maintenanceForm=document.getElementById('maintenance-form');
  if(maintenanceForm)maintenanceForm.onsubmit=event=>{
    const window={id:'m-'+(crypto.randomUUID?crypto.randomUUID():Date.now()),name:document.getElementById('maintenance-name').value,node:document.getElementById('maintenance-node').value,start:new Date(document.getElementById('maintenance-start').value).getTime()/1000,end:new Date(document.getElementById('maintenance-end').value).getTime()/1000};
    submitServiceForm(event,{action:'maintenance',windows:data.maintenance.concat(window)});
  };
  target.querySelectorAll('[data-remove-maintenance]').forEach(button=>button.onclick=async()=>{button.disabled=true;try{await saveServices({action:'maintenance',windows:data.maintenance.filter(window=>window.id!==button.dataset.removeMaintenance)})}catch(error){button.disabled=false;toast(error.message)}});
}
async function submitServiceForm(event,payload){
  event.preventDefault();const submit=event.target.querySelector('[type=submit]');submit.disabled=true;
  try{await saveServices(payload)}catch(error){const target=document.getElementById('service-error');if(target)target.textContent=tr(error.message);submit.disabled=false}
}
function editService(existing){
  state.serviceEditing=true;
  const service=existing||{id:'s-'+(crypto.randomUUID?crypto.randomUUID():Date.now()),name:'',node:'local',protocol:'http',target:'',port:443,status:200,match:'',interval:60,timeout:5,failures:3,enabled:true};
  const target=document.getElementById('service-editor');
  target.innerHTML='<form id="service-form" class="rule-editor"><div class="form-grid"><div class="field"><label for="service-name">'+esc(ft('service_name'))+'</label><input id="service-name" required maxlength="80" value="'+esc(service.name)+'"></div><div class="field"><label for="service-node">'+esc(ft('associated_asset'))+'</label><select id="service-node">'+serviceAssets().map(asset=>'<option value="'+esc(asset.id)+'" '+(service.node===asset.id?'selected':'')+'>'+esc(asset.name)+'</option>').join('')+'</select></div><div class="field"><label for="service-protocol">'+esc(ft('protocol'))+'</label><select id="service-protocol"><option value="http">HTTP / HTTPS</option><option value="tcp">TCP</option><option value="tls">'+esc(ft('tls_certificate'))+'</option></select></div><div class="field"><label for="service-target">'+esc(ft('target'))+'</label><input id="service-target" required maxlength="1024" value="'+esc(service.target)+'"></div><div class="field" id="service-port-field"><label for="service-port">TCP / TLS port</label><input id="service-port" type="number" min="1" max="65535" value="'+service.port+'"></div><div class="field hidden" id="service-certificate-field"><label for="service-certificate-days">'+esc(ft('certificate_warning'))+'</label><select id="service-certificate-days"><option value="30">30</option><option value="14">14</option><option value="7">7</option></select></div><div class="field" id="service-status-field"><label for="service-status">'+esc(ft('expected_status'))+'</label><input id="service-status" type="number" min="200" max="599" value="'+service.status+'"></div><div class="field full" id="service-match-field"><label for="service-match">'+esc(ft('content_match'))+'</label><input id="service-match" maxlength="128" value="'+esc(service.match)+'"></div><div class="field"><label for="service-interval">'+esc(ft('interval_seconds'))+'</label><input id="service-interval" type="number" required min="30" max="3600" value="'+service.interval+'"></div><div class="field"><label for="service-timeout">'+esc(ft('timeout_seconds'))+'</label><input id="service-timeout" type="number" required min="1" max="10" step="any" value="'+service.timeout+'"></div><div class="field"><label for="service-failures">'+esc(ft('failure_threshold'))+'</label><input id="service-failures" type="number" required min="1" max="10" value="'+service.failures+'"></div><label class="checkbox-label"><input id="service-enabled" type="checkbox" '+(service.enabled?'checked':'')+'>'+esc(ft('enabled'))+'</label></div><p class="helper">'+esc(ft('probe_help'))+' '+esc(ft('service_edit_help'))+'</p><p id="service-error" class="error-message" role="alert"></p><div class="modal-actions"><button type="button" class="button subtle" id="service-cancel">'+esc(ft('cancel'))+'</button><button type="submit" class="button primary">'+esc(ft('save'))+'</button></div></form>';
  const protocol=document.getElementById('service-protocol');protocol.value=service.protocol;
  document.getElementById('service-certificate-days').value=String(service.cert_days||30);
  function updateFields(){
    const tcp=protocol.value!=='http';
    document.getElementById('service-certificate-field').classList.toggle('hidden',protocol.value!=='tls');
    document.getElementById('service-port-field').classList.toggle('hidden',!tcp);
    document.getElementById('service-status-field').classList.toggle('hidden',tcp);
    document.getElementById('service-match-field').classList.toggle('hidden',tcp);
    document.getElementById('service-target').placeholder=tcp?'127.0.0.1':'https://example.com/health';
  }
  protocol.onchange=updateFields;updateFields();
  document.getElementById('service-cancel').onclick=()=>{state.serviceEditing=false;renderServices()};
  document.getElementById('service-form').onsubmit=event=>{
    const next={id:service.id,name:document.getElementById('service-name').value,node:document.getElementById('service-node').value,protocol:protocol.value,target:document.getElementById('service-target').value,port:Number(document.getElementById('service-port').value),status:Number(document.getElementById('service-status').value),match:document.getElementById('service-match').value,interval:Number(document.getElementById('service-interval').value),timeout:Number(document.getElementById('service-timeout').value),failures:Number(document.getElementById('service-failures').value),cert_days:Number(document.getElementById('service-certificate-days').value),enabled:document.getElementById('service-enabled').checked};
    submitServiceForm(event,{action:'services',services:state.serviceData.services.filter(item=>item.id!==service.id).concat(next)});
  };
  document.getElementById('service-name').focus({preventScroll:true});
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
        _cleanup_auth_state(now)
        expiry = SESSIONS.get(token, 0)
        if expiry <= now:
            SESSIONS.pop(token, None)
            return False
        SESSIONS[token] = now + 12 * 60 * 60
    return True


def _cleanup_auth_state(now=None):
    """Bound in-memory authentication state and discard expired entries."""
    global AUTH_STATE_LAST_CLEANUP
    now = time.time() if now is None else now
    if now - AUTH_STATE_LAST_CLEANUP < AUTH_STATE_CLEANUP_INTERVAL:
        return
    for token, expiry in list(SESSIONS.items()):
        if expiry <= now:
            SESSIONS.pop(token, None)
    for address, failures in list(LOGIN_FAILURES.items()):
        recent = [stamp for stamp in failures if now - stamp < 60]
        if recent:
            LOGIN_FAILURES[address] = recent
        else:
            LOGIN_FAILURES.pop(address, None)
    if len(SESSIONS) > MAX_ACTIVE_SESSIONS:
        oldest = sorted(SESSIONS.items(), key=lambda item: item[1])
        for token, _ in oldest[:len(SESSIONS) - MAX_ACTIVE_SESSIONS]:
            SESSIONS.pop(token, None)
    if len(LOGIN_FAILURES) > MAX_LOGIN_FAILURE_ADDRESSES:
        oldest = sorted(LOGIN_FAILURES, key=lambda address: max(LOGIN_FAILURES[address]))
        for address in oldest[:len(LOGIN_FAILURES) - MAX_LOGIN_FAILURE_ADDRESSES]:
            LOGIN_FAILURES.pop(address, None)
    AUTH_STATE_LAST_CLEANUP = now


def _remember_login_failure(address, now):
    """Record a failure without allowing distinct source addresses to grow unbounded."""
    if address not in LOGIN_FAILURES and len(LOGIN_FAILURES) >= MAX_LOGIN_FAILURE_ADDRESSES:
        LOGIN_FAILURES.pop(next(iter(LOGIN_FAILURES)), None)
    LOGIN_FAILURES.setdefault(address, []).append(now)


def _setup_token_matches(supplied):
    return bool(SETUP_TOKEN and isinstance(supplied, str)
                and secrets.compare_digest(supplied, SETUP_TOKEN))


def _session_cookie(token, max_age):
    cookie = "tw_session=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d" % (token, max_age)
    return cookie + ("; Secure" if SECURE_COOKIE else "")


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
        # Request bodies may contain credentials; log only the request line.
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
        if path == "/api/backup":
            if not self._require_session():
                return
            if not BACKUP_LOCK.acquire(blocking=False):
                self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "A backup is already in progress"})
                return
            headers_sent = False
            try:
                with tempfile.TemporaryFile(dir=STORE.path.parent) as output:
                    STORE.export_backup(output)
                    length = output.tell()
                    output.seek(0)
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Length", str(length))
                    self.send_header("Content-Disposition", 'attachment; filename="tinywatch-backup.zip"')
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    headers_sent = True
                    shutil.copyfileobj(output, self.wfile, length=65536)
            except (OSError, ValueError):
                # A disconnected download must not receive a second HTTP response.
                if headers_sent:
                    self.close_connection = True
                else:
                    self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Backup unavailable; check disk space and the 512 MiB limit"})
            finally:
                BACKUP_LOCK.release()
            return
        if path == "/api/config":
            if not self._require_session():
                return
            self._json(HTTPStatus.OK, _config_for_browser())
            return
        if path == "/api/alerts":
            if self._require_session():
                self._json(HTTPStatus.OK, _alerts_response())
            return
        if path == "/api/diagnostics":
            if not self._require_session():
                return
            try:
                self._json(HTTPStatus.OK, _diagnostics_response(collect_cluster_snapshot()))
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": _safe_text(exc, 180)})
            return
        if path == "/api/metrics":
            if not self._require_session():
                return
            _dashboard_activity()
            try:
                snapshot = collect_cluster_snapshot()
                self._json(HTTPStatus.OK, dict(snapshot, diagnostics=_diagnostics_response(snapshot),
                                               alerts=_alert_counts()))
            except Exception as exc:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": _safe_text(exc, 180)})
            return
        if path == "/api/capacity":
            if not self._require_session():
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                self._json(HTTPStatus.OK, _capacity_forecasts(query.get("node", ["local"])[0]))
            except (ValueError, OSError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "Capacity history unavailable"})
            return
        if path == "/api/services":
            if self._require_session():
                self._json(HTTPStatus.OK, _service_response())
            return
        if path == "/api/flight":
            if not self._require_session():
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                self._json(HTTPStatus.OK, _flight_response(query.get("incident", [""])[0]))
            except ValueError:
                self._json(HTTPStatus.NOT_FOUND, {"error": "No retained flight record"})
            return
        if path == "/api/comparison":
            if not self._require_session():
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                self._json(HTTPStatus.OK, _change_comparison(query.get("node", ["local"])[0],
                           _finite_value(query.get("center", [None])[0]), _finite_value(query.get("span", [1800])[0])))
            except (ValueError, OSError):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "Comparison unavailable; check the time and retention window"})
            return
        if path == "/api/investigation":
            if not self._require_session():
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            try:
                partition = query.get("partition", [""])[0]
                if partition and not re.fullmatch(r"[a-f0-9]{24}", partition):
                    raise ValueError("Invalid partition")
                self._json(HTTPStatus.OK, _investigation_response(query.get("node", ["local"])[0],
                           float(query.get("start", [""])[0]), float(query.get("end", [""])[0]), partition))
            except (TypeError, ValueError, OverflowError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_text(exc, 180)})
            except OSError:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "History unavailable; check diagnostics"})
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
                partition = query.get("partition", [""])[0]
                if partition and not re.fullmatch(r"[a-f0-9]{24}", partition):
                    raise ValueError("Invalid partition")
                self._json(HTTPStatus.OK, _history_response(node_id, metric, range_name, interface[:120], start, end, partition))
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_text(exc, 180)})
            except OSError:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "History unavailable; check diagnostics"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "未找到"})

    def do_POST(self):
        global SETUP_TOKEN
        path = urllib.parse.urlsplit(self.path).path
        try:
            value = self._read_json()
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_text(exc, 180)})
            return

        if path == "/api/heartbeat":
            try:
                ok = _receive_heartbeat(value, self.headers.get("X-TinyWatch-Heartbeat", ""))
                self._json(HTTPStatus.OK if ok else HTTPStatus.FORBIDDEN, {"ok": ok})
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except OSError:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Heartbeat could not be persisted"})
            return
        if path == "/api/setup":
            with STORE.lock:
                if STORE.data.get("password") is not None:
                    self._json(HTTPStatus.CONFLICT, {"error": "管理员密码已设置"})
                    return
                if not _setup_token_matches(value.get("setup_token")):
                    self._json(HTTPStatus.FORBIDDEN, {"error": "首次设置代码无效或已过期"})
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
                SETUP_TOKEN = None
            self._create_session()
            return

        if path == "/api/login":
            address = self.client_address[0] if self.client_address else "unknown"
            now = time.time()
            with STATE_LOCK:
                _cleanup_auth_state(now)
                recent = [stamp for stamp in LOGIN_FAILURES.get(address, []) if now - stamp < 60]
                if recent:
                    LOGIN_FAILURES[address] = recent
                else:
                    LOGIN_FAILURES.pop(address, None)
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
                    _remember_login_failure(address, now)
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
            self._json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": _session_cookie("", 0)})
            return
        if path == "/api/alerts/preview":
            if not PREVIEW_LOCK.acquire(blocking=False):
                self._json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "A rule preview is already running"})
                return
            try:
                self._json(HTTPStatus.OK, _preview_rule(value))
            except (ValueError, OSError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": _safe_text(exc, 180)})
            finally:
                PREVIEW_LOCK.release()
            return
        if path == "/api/services":
            try:
                self._json(HTTPStatus.OK, _save_services(value))
            except ConfigurationConflict as exc:
                self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except OSError:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Configuration could not be persisted"})
            return
        if path == "/api/annotations":
            try:
                self._json(HTTPStatus.OK, _add_annotation(value))
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        if path == "/api/config":
            try:
                self._save_config(value)
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except OSError:
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Configuration could not be persisted"})
                return
            self._json(HTTPStatus.OK, {"ok": True})
            return
        if path == "/api/alerts":
            try:
                if value.get("action") == "save_rules":
                    _save_alert_rules(value.get("rules"))
                elif value.get("action") == "ack":
                    if not _acknowledge_incident(value.get("id")):
                        self._json(HTTPStatus.NOT_FOUND, {"error": "Incident not found"})
                        return
                else:
                    raise ValueError("Invalid alert action")
            except ValueError as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._json(HTTPStatus.OK, _alerts_response())
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "未找到"})

    def _create_session(self):
        token = secrets.token_urlsafe(32)
        with STATE_LOCK:
            _cleanup_auth_state()
            if len(SESSIONS) >= MAX_ACTIVE_SESSIONS:
                oldest = min(SESSIONS, key=SESSIONS.get)
                SESSIONS.pop(oldest, None)
            SESSIONS[token] = time.time() + 12 * 60 * 60
        self._json(HTTPStatus.OK, {"ok": True}, {"Set-Cookie": _session_cookie(token, 43200)})

    def _save_config(self, value):
        with STORE.lock:
            previous = STORE.data
            STORE.data = _configuration_candidate(previous)
            try:
                return self._apply_config(value)
            except Exception:
                STORE.data = previous
                raise

    def _apply_config(self, value):
        raw_assets = value.get("assets", [])
        raw_widgets = value.get("widgets", [])
        if not isinstance(raw_assets, list) or len(raw_assets) > MAX_ASSETS:
            raise ValueError("最多配置 %d 个远程资产" % MAX_ASSETS)
        if not isinstance(raw_widgets, list) or len(raw_widgets) > MAX_WIDGETS:
            raise ValueError("监控卡片最多 %d 张" % MAX_WIDGETS)
        flight_enabled = value.get("flight_enabled", STORE.data.get("flight_enabled", False))
        if not isinstance(flight_enabled, bool):
            raise ValueError("Invalid flight recorder setting")
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
            STORE.data["flight_enabled"] = flight_enabled
            if not flight_enabled:
                for record in STORE.data.get("flight_records", []):
                    if record["status"] == "recording":
                        record["status"] = "stopped"
            removed_nodes = set(previous) - identifiers
            for node_id in removed_nodes:
                STORE.data.get("node_fingerprints", {}).pop(node_id, None)
            removed_services = {item["id"] for item in STORE.data.get("services", []) if item["node"] in removed_nodes}
            STORE.data["services"] = [item for item in STORE.data.get("services", []) if item["id"] not in removed_services]
            removed_jobs = {item["id"] for item in STORE.data.get("heartbeats", []) if item["node"] in removed_nodes}
            STORE.data["heartbeats"] = [item for item in STORE.data.get("heartbeats", []) if item["id"] not in removed_jobs]
            removed_services |= removed_jobs
            STORE.data["service_revision"] = STORE.data.get("service_revision", 0) + 1
            STORE.data["maintenance"] = [item for item in STORE.data.get("maintenance", []) if item["node"] not in removed_nodes]
            for identity in removed_services:
                STORE.data.get("service_states", {}).pop(identity, None)
                STORE.data.get("service_history", {}).pop(identity, None)
                STORE.mark_history_dirty()
            for incident in STORE.data.get("incidents", []):
                if incident.get("status") == "active" and incident.get("node") in removed_nodes:
                    _resolve_incident(incident, time.time(), "asset_removed")
            STORE.data["alert_rules"] = [rule for rule in STORE.data.get("alert_rules", [])
                                          if rule.get("node") not in removed_nodes]
            STORE.data["alert_states"] = {key: item for key, item in STORE.data.get("alert_states", {}).items()
                                           if key.split(":", 1)[-1] not in removed_nodes}
            retention_cutoff = time.time() - retention_days * 24 * 60 * 60
            pruned = _prune_history_database(STORE.data, retention_cutoff)
            backup_retention_days = retention_days if pruned or previous_retention_days != retention_days else None
            STORE.save(backup_retention_days=backup_retention_days)
        _invalidate_cluster_snapshot()


class TinyWatchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.request_slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        return request, address

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


def main(argv=None):
    parser = argparse.ArgumentParser(description="TinyWatch - dependency-free server monitoring dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="listen address; use 0.0.0.0 for LAN access")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="HTTP listening port (default: %(default)s)")
    parser.add_argument("--data", default=str(default_store_path()), help="JSON database path (default: ~/.tinywatch/data.json)")
    commands = parser.add_mutually_exclusive_group()
    commands.add_argument("--backup", metavar="ZIP", help="export a backup and exit; stop the server first")
    commands.add_argument("--restore-backup", metavar="ZIP", help="restore into a new --data directory and exit")
    parser.add_argument("--secure-cookie", action="store_true",
                        help="mark session cookies Secure when HTTPS is terminated by a trusted proxy")
    parser.add_argument("--version", action="version", version=APP_NAME + " " + APP_VERSION)
    parser.add_argument("--probe-worker", choices=("asset", "service"), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.probe_worker:
        configuration = json.loads(sys.stdin.buffer.read(32768))
        if not isinstance(configuration, dict):
            parser.error("Invalid probe input")
        result = (_remote_snapshot_direct(configuration) if args.probe_worker == "asset"
                  else _probe_service_direct(configuration))
        sys.stdout.write(json.dumps(result, ensure_ascii=False))
        return 0
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    global STORE, SETUP_TOKEN, SECURE_COOKIE, DETAILS_RUNNING
    if args.restore_backup:
        try:
            restored = restore_backup(args.restore_backup, args.data)
        except (OSError, ValueError, zipfile.BadZipFile, EOFError, KeyError, TypeError) as exc:
            parser.error(str(exc))
        print("Restored database: " + str(restored))
        return 0
    if args.backup:
        output = Path(args.backup)
        if not Path(args.data).is_file():
            parser.error("Backup source database does not exist")
        if output.exists():
            parser.error("Backup destination already exists")
        created = False
        try:
            with output.open("xb") as stream:
                created = True
                os.chmod(output, 0o600)
                JsonStore(args.data).export_backup(stream)
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, ValueError) as exc:
            if created:
                output.unlink(missing_ok=True)
            parser.error(str(exc))
        print("Backup saved: " + str(output))
        return 0
    try:
        STORE = JsonStore(args.data)
        SETUP_TOKEN = secrets.token_urlsafe(24) if STORE.data.get("password") is None else None
        SECURE_COOKIE = bool(args.secure_cookie)
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
    if SETUP_TOKEN:
        print("One-time first-run setup code: " + SETUP_TOKEN)
        print("Enter this code in the setup page. It expires when TinyWatch stops.")
    if SECURE_COOKIE:
        print("Secure session cookies enabled; access this instance through HTTPS.")
    if args.host in ("0.0.0.0", "::"):
        print("LAN mode enabled; protect access with a firewall and use HTTPS via a trusted reverse proxy.")
    history_stop = threading.Event()
    history_thread = threading.Thread(target=_worker_entry, args=("history", _history_sampler, history_stop),
                                      name="tinywatch-history", daemon=True)
    DETAILS_RUNNING = True
    workers = [threading.Thread(target=_worker_entry, args=(name[len("tinywatch-"):], target, history_stop), name=name, daemon=True)
               for target, name in ((_details_sampler, "tinywatch-details"), (_service_sampler, "tinywatch-services"),
                                    (_notification_sampler, "tinywatch-notifications"), (_asset_sampler, "tinywatch-assets"),
                                    (_flight_sampler, "tinywatch-flight"))]
    for worker in workers:
        worker.start()
    history_thread.start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nStopping TinyWatch…")
    finally:
        history_stop.set()
        history_thread.join(timeout=45)
        for worker in workers:
            worker.join(timeout=10)
        DETAILS_RUNNING = False
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

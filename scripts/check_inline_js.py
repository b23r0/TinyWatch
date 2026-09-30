"""Parse the inline UI JavaScript without adding a frontend runtime dependency."""

import subprocess
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = PROJECT_ROOT / "tinywatch.py"


def extract_inline_script(source):
    page_marker = "HTML_PAGE = r'''"
    page_start = source.find(page_marker)
    if page_start < 0:
        raise ValueError("HTML_PAGE raw string was not found")
    page_start += len(page_marker)
    page_end = source.find("'''", page_start)
    if page_end < 0:
        raise ValueError("HTML_PAGE raw string is not terminated")
    page = source[page_start:page_end]
    script_marker = "<script>"
    script_start = page.find(script_marker)
    script_end = page.find("</script>", script_start + len(script_marker))
    if script_start < 0 or script_end < 0:
        raise ValueError("embedded UI script was not found")
    return page[script_start + len(script_marker):script_end]


def main():
    script = extract_inline_script(SOURCE_PATH.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="tinywatch-js-") as directory:
        script_path = Path(directory) / "inline-ui.js"
        script_path.write_text(script, encoding="utf-8")
        subprocess.run(["node", "--check", str(script_path)], check=True)

        helper_start = script.find("function downsampleHistory(")
        helper_end = script.find("\nfunction chartTimeLabel(", helper_start)
        if helper_start < 0 or helper_end < 0:
            raise ValueError("downsampleHistory helper was not found")
        helper = script[helper_start:helper_end]
        chart_test = Path(directory) / "chart-regression.js"
        chart_test.write_text(
            "const assert = require('node:assert/strict');\n"
            "const CHART_GAP_SECONDS = 90;\n"
            + helper
            + "\nconst samples = Array.from({length: 1000}, (_, index) => ({"
            "timestamp: index * 60 + (index >= 500 ? 3600 : 0), "
            "value: index === 234 ? 500 : (index === 721 ? 180 : 12)}));\n"
            "const reduced = downsampleHistory(samples, 240);\n"
            "assert.ok(reduced.length <= 240);\n"
            "assert.ok(reduced.some(point => point.timestamp === samples[234].timestamp), 'peak is preserved');\n"
            "assert.ok(reduced.some(point => point.timestamp === samples[499].timestamp), 'gap start is preserved');\n"
            "assert.ok(reduced.some(point => point.timestamp === samples[500].timestamp), 'gap end is preserved');\n"
            "assert.deepEqual(reduced.map(point => point.timestamp), reduced.map(point => point.timestamp).slice().sort((a, b) => a - b));\n",
            encoding="utf-8",
        )
        subprocess.run(["node", str(chart_test)], check=True)


if __name__ == "__main__":
    main()

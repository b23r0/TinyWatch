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

        helper_start = script.find("function chartHasGap(")
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

        # Execute pure presentation functions without a browser or network calls.
        # Sparse compacted samples must not be mistaken for a collection outage.
        ui_test = Path(directory) / "ui-regression.js"
        if script.count("\nboot();") != 1:
            raise ValueError("expected one application bootstrap call")
        ui_test.write_text(
            "const assert = require('node:assert/strict');\n"
            "const document = {getElementById: () => ({}), documentElement: {}};\n"
            "const localStorage = {getItem: () => null};\n"
            + script.replace("\nboot();", "")
            + "\nfor (const language of ['en','zh','ja','fr','ru','de']) {\n"
            "  state.language = language;\n"
            "  for (const [key, row] of Object.entries(FEATURE_MESSAGES)) {\n"
            "    assert.equal(row.length, 6); assert.ok(ft(key)); assert.equal(ft(key), row[({en:0,zh:1,ja:2,fr:3,ru:4,de:5})[language]]);\n"
            "  }\n"
            "}\nstate.language = 'en';\n"
            "const compacted = Array.from({length: 400}, (_, index) => ({timestamp:index*600,value:index%7,gapBefore:index===210}));\n"
            "const sparse = downsampleHistory(compacted, 240);\n"
            "assert.equal(sparse.filter(point => point.gapBefore).length, 1);\n"
            "const chart = sparkline(compacted, 'cpu');\n"
            "assert.equal((chart.match(/class=\"chart-gap-mark\"/g)||[]).length, 1);\n"
            "assert.ok(!sparkline(compacted.map(point => ({...point,gapBefore:false})), 'cpu').includes('class=\"chart-gap-mark\"'));\n"
            "const manyGaps = Array.from({length:1000}, (_,index) => ({timestamp:index*60,value:index===17?900:12,gapBefore:index>0&&index%2===0}));\n"
            "const crowded = downsampleHistory(manyGaps,240); assert.ok(crowded.length<=240);\n"
            "assert.ok(crowded.some(point => point.value===900), 'outage boundaries cannot consume the peak budget');\n"
            "const incident = incidentCard({id:'1',rule_name:'<img src=x>',node_name:'<script>',metric:'cpu',mode:'threshold',status:'active',triggered_at:1,threshold:90,last_value:95,peak:95,context:{processes:[],logins:[{kind:'SSH',message:'<svg onload=x>'}]}});\n"
            "assert.ok(!incident.includes('<img src=x>')); assert.ok(incident.includes('&lt;img src=x&gt;'));\n"
            "assert.ok(!incident.includes('<svg onload=x>')); assert.ok(incident.includes('Acknowledge'));\n",
            encoding="utf-8",
        )
        subprocess.run(["node", str(ui_test)], check=True)


if __name__ == "__main__":
    main()

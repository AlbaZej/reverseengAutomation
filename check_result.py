"""Quick utility: query an analysis job and print findings."""
import json
import sys
import urllib.request

job_id = sys.argv[1] if len(sys.argv) > 1 else "06e12912-8369-41d6-9ace-b528af4627c5"

url = f"http://127.0.0.1:8000/api/analysis/{job_id}"
with urllib.request.urlopen(url) as resp:
    d = json.loads(resp.read())

print(f"Status: {d.get('status')}")
r = d.get("report", {})

if not r:
    print("No report yet")
    sys.exit(0)

print(f"VERDICT: {r['verdict'].upper()} ({r['verdict_confidence']*100:.0f}%)")
print(f"Findings: {len(r['findings'])}, IOCs: {len(r['iocs'])}")
print()
print("Findings:")
for f in r["findings"][:25]:
    print(f"  [{f['severity'].upper():8}] {f['title']}: {f['description'][:80]}")

print()
print("Tool execution:")
for t in r.get("tool_results", []):
    s = "OK" if t["success"] else "FAIL"
    print(f"  {s:4} {t['tool']:22} {t['duration_seconds']}s")
    contained = t.get("data", {}).get("contained")
    if contained:
        for c in contained:
            print(f"      -> {(c.get('path') or '?')[:55]}")
            print(f"         type={c.get('file_type')}, verdict={c.get('verdict')}, findings={c.get('findings')}")

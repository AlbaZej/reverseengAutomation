"""Detailed result viewer."""
import json
import sys
import urllib.request

job_id = sys.argv[1] if len(sys.argv) > 1 else open("/tmp/last_job.txt").read().strip()
url = f"http://127.0.0.1:8000/api/analysis/{job_id}"
with urllib.request.urlopen(url) as resp:
    d = json.loads(resp.read())

r = d.get("report", {})
print(f"VERDICT: {r['verdict'].upper()} ({r['verdict_confidence']*100:.0f}%)")
print()
print(f"Findings:     {len(r.get('findings', []))}")
print(f"YARA matches: {len(r.get('yara_matches', []))}")
print(f"IOCs:         {len(r.get('iocs', []))}")
print(f"Functions:    {len(r.get('functions', []))}")
print(f"Imports:      {len(r.get('imports', []))}")
print(f"Strings:      {len(r.get('strings', {}).get('interesting', []))}")
print()

if r.get("yara_matches"):
    print("YARA matches:")
    for m in r["yara_matches"]:
        print(f"  - {m['rule']}: {m.get('meta', {}).get('description', '')}")
    print()

if r.get("functions"):
    print(f"First 10 functions:")
    for f in r["functions"][:10]:
        marker = "★" if f.get("is_interesting") else " "
        tags = ",".join(f.get("tags", [])[:3])
        print(f"  {marker} 0x{f.get('address', 0):08x}  {f['name'][:60]}  [{tags}]")
    print()

print("Findings:")
for f in r.get("findings", [])[:15]:
    print(f"  [{f['severity'].upper():8}] {f['title'][:90]}")

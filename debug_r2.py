"""Inspect axfj output with correct addresses."""
import json
import os

os.environ["PATH"] = (
    r"C:\Users\pc\Documents\reverseengAutomation\.tools\radare2-6.1.4-w64\bin;"
    + os.environ["PATH"]
)
import r2pipe

target = r"C:\Users\pc\AppData\Local\Temp\deshifro_archive_gx59gztw\GameBox.exe"
print(f"Using: {target}")
print()

r2 = r2pipe.open(target, flags=["-2"])
r2.cmd("aa")
r2.cmd("aac")

funcs = json.loads(r2.cmd("aflj") or "[]")
print(f"Functions: {len(funcs)}")

# Find functions with xrefs
found = 0
for f in funcs:
    addr = f.get("addr") or f.get("offset", 0)
    name = f.get("name", "")
    xrefs = json.loads(r2.cmd(f"axfj @{addr}") or "[]")
    if xrefs and found < 3:
        found += 1
        print(f"\nFn {name} @ 0x{addr:x}: {len(xrefs)} xrefs")
        for x in xrefs[:5]:
            print(f"  xref keys: {list(x.keys())}")
            print(f"  xref data: {x}")
    if found >= 3:
        break

# Also try axt to see TO references on imports
print("\n\nNow looking for refs TO an import...")
imports = json.loads(r2.cmd("iij") or "[]")
for imp in imports[:5]:
    name = imp.get("name", "")
    plt = imp.get("plt", 0)
    bind = imp.get("bind", "")
    print(f"\nImport: {name} (plt={hex(plt) if plt else '0'}, bind={bind})")
    if plt:
        refs = json.loads(r2.cmd(f"axtj {plt}") or "[]")
        print(f"  refs TO this import: {len(refs)}")
        for r in refs[:2]:
            print(f"    {r}")

r2.quit()

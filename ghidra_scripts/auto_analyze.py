# Ghidra headless script: auto-analyze a binary and export results as JSON.
# Run via: analyzeHeadless ... -postScript auto_analyze.py <output_path>
#
# This script runs inside Ghidra's Jython environment.
# Ghidra globals (currentProgram, getMonitor, etc.) are available implicitly.

import json
import sys

# The output path is passed as the first script argument
args = getScriptArgs()
if not args:
    print("ERROR: No output path provided")
    sys.exit(1)

output_path = args[0]

program = currentProgram
listing = program.getListing()
fm = program.getFunctionManager()
dtm = program.getDataTypeManager()

# Suspicious API categories
SUSPICIOUS_APIS = {
    "network": [
        "WSAStartup", "socket", "connect", "send", "recv", "bind", "listen", "accept",
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpOpenRequestA", "HttpSendRequestA", "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
    ],
    "file": [
        "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
        "CopyFileA", "MoveFileA", "GetTempPathA",
    ],
    "process": [
        "CreateProcessA", "CreateProcessW", "OpenProcess", "TerminateProcess",
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
        "ShellExecuteA", "ShellExecuteW", "WinExec",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptDeriveKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
    ],
    "registry": [
        "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegDeleteKeyA",
    ],
    "anti-debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA",
    ],
}

# Flatten for quick lookup
API_CATEGORY = {}
for cat, apis in SUSPICIOUS_APIS.items():
    for api in apis:
        API_CATEGORY[api] = cat


def get_imports():
    """Extract imported functions."""
    imports = []
    st = program.getSymbolTable()
    for sym in st.getExternalSymbols():
        name = sym.getName()
        parent = sym.getParentNamespace()
        library = parent.getName() if parent else ""
        category = API_CATEGORY.get(name, "")
        imports.append({
            "name": name,
            "library": library,
            "is_suspicious": name in API_CATEGORY,
            "category": category,
        })
    return imports


def get_exports():
    """Extract exported functions."""
    exports = []
    st = program.getSymbolTable()
    for sym in st.getSymbolIterator():
        if sym.isExternalEntryPoint():
            exports.append({
                "name": sym.getName(),
                "address": sym.getAddress().getOffset(),
            })
    return exports


def get_functions(max_decompile=50):
    """Extract and decompile functions."""
    from ghidra.app.decompiler import DecompInterface

    decomp = DecompInterface()
    decomp.openProgram(program)

    functions = []
    interesting_count = 0

    for func in fm.getFunctions(True):
        name = func.getName()
        addr = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()

        # Determine if interesting
        tags = []
        is_interesting = False

        # Check if function calls suspicious APIs
        called_funcs = []
        ref_iter = func.getCalledFunctions(getMonitor())
        for called in ref_iter:
            called_name = called.getName()
            called_funcs.append(called_name)
            if called_name in API_CATEGORY:
                tags.append(API_CATEGORY[called_name])
                is_interesting = True

        # Get callers
        callers = [f.getName() for f in func.getCallingFunctions(getMonitor())]

        func_data = {
            "name": name,
            "address": addr,
            "size": size,
            "calls": called_funcs,
            "called_by": callers,
            "is_interesting": is_interesting,
            "tags": list(set(tags)),
            "decompiled": "",
        }

        # Only decompile interesting functions + first N functions
        if is_interesting or interesting_count < max_decompile:
            result = decomp.decompileFunction(func, 30, getMonitor())
            if result and result.depiledFunction():
                func_data["decompiled"] = result.getDecompiledFunction().getC()
            interesting_count += 1

        functions.append(func_data)

    decomp.dispose()
    return functions


# Build output
output = {
    "entry_point": program.getImageBase().getOffset(),
    "architecture": program.getLanguage().getProcessor().toString(),
    "imports": get_imports(),
    "exports": get_exports(),
    "functions": get_functions(),
}

# Write JSON
with open(output_path, "w") as f:
    json.dump(output, f, indent=2, default=str)

print("Deshifro: Analysis complete. Output written to: " + output_path)

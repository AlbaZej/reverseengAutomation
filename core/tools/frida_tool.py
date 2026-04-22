"""Frida dynamic analysis tool — runtime instrumentation and behavior capture."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from core.models import ToolResult
from core.tools.base import BaseTool

# Frida script that hooks common APIs and logs calls
HOOK_SCRIPT = r"""
'use strict';

const hooks = [];
const MAX_EVENTS = 5000;
let eventCount = 0;

function log(category, name, args, retval) {
    if (eventCount >= MAX_EVENTS) return;
    eventCount++;
    send({
        type: 'api_call',
        timestamp: Date.now(),
        category: category,
        name: name,
        args: args || [],
        retval: retval || null
    });
}

// --- File operations ---
const fileApis = ['CreateFileA', 'CreateFileW', 'ReadFile', 'WriteFile',
                  'DeleteFileA', 'DeleteFileW', 'CopyFileA', 'MoveFileA'];
fileApis.forEach(function(name) {
    try {
        var addr = Module.findExportByName('kernel32.dll', name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.name = name;
                    if (name.endsWith('A') || name.endsWith('W')) {
                        this.path = name.endsWith('W') ? args[0].readUtf16String() : args[0].readUtf8String();
                    }
                },
                onLeave: function(retval) {
                    log('file', this.name, [this.path || ''], retval.toInt32());
                }
            });
        }
    } catch(e) {}
});

// --- Network operations ---
const netApis = ['connect', 'send', 'recv', 'WSAStartup', 'getaddrinfo'];
['ws2_32.dll', 'wsock32.dll'].forEach(function(dll) {
    netApis.forEach(function(name) {
        try {
            var addr = Module.findExportByName(dll, name);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function(args) { this.name = name; },
                    onLeave: function(retval) {
                        log('network', this.name, [], retval.toInt32());
                    }
                });
            }
        } catch(e) {}
    });
});

// --- Registry operations ---
const regApis = ['RegOpenKeyExA', 'RegOpenKeyExW', 'RegSetValueExA',
                 'RegSetValueExW', 'RegCreateKeyExA'];
regApis.forEach(function(name) {
    try {
        var addr = Module.findExportByName('advapi32.dll', name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.name = name;
                    try {
                        this.key = name.endsWith('W') ? args[1].readUtf16String() : args[1].readUtf8String();
                    } catch(e) { this.key = ''; }
                },
                onLeave: function(retval) {
                    log('registry', this.name, [this.key || ''], retval.toInt32());
                }
            });
        }
    } catch(e) {}
});

// --- Process operations ---
const procApis = ['CreateProcessA', 'CreateProcessW', 'OpenProcess',
                  'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
                  'ShellExecuteA', 'ShellExecuteW'];
procApis.forEach(function(name) {
    try {
        var addr = Module.findExportByName('kernel32.dll', name) ||
                   Module.findExportByName('shell32.dll', name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) {
                    this.name = name;
                    try {
                        if (name.includes('Process') && name.includes('Create')) {
                            this.cmdline = name.endsWith('W') ? args[1].readUtf16String() : args[1].readUtf8String();
                        }
                    } catch(e) { this.cmdline = ''; }
                },
                onLeave: function(retval) {
                    log('process', this.name, [this.cmdline || ''], retval.toInt32());
                }
            });
        }
    } catch(e) {}
});

// --- Anti-debug detection ---
const antiDbg = ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
                 'NtQueryInformationProcess'];
antiDbg.forEach(function(name) {
    try {
        var addr = Module.findExportByName('kernel32.dll', name) ||
                   Module.findExportByName('ntdll.dll', name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function() { this.name = name; },
                onLeave: function(retval) {
                    log('anti_debug', this.name, [], retval.toInt32());
                    // Lie to anti-debug checks
                    if (this.name === 'IsDebuggerPresent') {
                        retval.replace(ptr(0));
                    }
                }
            });
        }
    } catch(e) {}
});

// --- Crypto operations ---
const cryptoApis = ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt'];
cryptoApis.forEach(function(name) {
    try {
        var addr = Module.findExportByName('advapi32.dll', name) ||
                   Module.findExportByName('bcrypt.dll', name);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function() { this.name = name; },
                onLeave: function(retval) {
                    log('crypto', this.name, [], retval.toInt32());
                }
            });
        }
    } catch(e) {}
});
"""


class FridaTool(BaseTool):
    name = "frida"
    description = "Dynamic analysis via Frida — runtime API hooking and behavior capture"
    supported_types = ["pe", "elf", "macho"]

    def __init__(self, timeout_seconds: int = 30):
        self.timeout = timeout_seconds

    def is_available(self) -> bool:
        try:
            import frida  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, target: Path, **kwargs) -> ToolResult:
        if not self.is_available():
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error="frida not installed. Install with: pip install frida frida-tools",
            )

        timeout = kwargs.get("timeout", self.timeout)

        try:
            return self._run_with_frida(target, timeout)
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                success=False,
                duration_seconds=0,
                error=f"Frida analysis failed: {e}",
            )

    def _run_with_frida(self, target: Path, timeout: int) -> ToolResult:
        import frida

        events = []
        process_exited = False

        def on_message(message, data):
            if message["type"] == "send":
                events.append(message["payload"])
            elif message["type"] == "error":
                events.append({"type": "error", "description": message["description"]})

        # Spawn the process suspended
        pid = frida.spawn([str(target)])
        session = frida.attach(pid)

        script = session.create_script(HOOK_SCRIPT)
        script.on("message", on_message)
        script.load()

        # Resume and let it run
        frida.resume(pid)

        start = time.time()
        try:
            while time.time() - start < timeout:
                time.sleep(0.5)
                # Check if process is still alive
                try:
                    session.enumerate_modules()
                except frida.InvalidOperationError:
                    process_exited = True
                    break
        finally:
            try:
                frida.kill(pid)
            except Exception:
                pass

        # Categorize events
        categories = {}
        for evt in events:
            if isinstance(evt, dict) and "category" in evt:
                cat = evt["category"]
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(evt)

        return ToolResult(
            tool_name=self.name,
            success=True,
            duration_seconds=time.time() - start,
            data={
                "total_events": len(events),
                "process_exited_early": process_exited,
                "runtime_seconds": round(time.time() - start, 2),
                "categories": {k: len(v) for k, v in categories.items()},
                "events": events[:5000],  # cap at 5k
                "file_operations": categories.get("file", []),
                "network_operations": categories.get("network", []),
                "registry_operations": categories.get("registry", []),
                "process_operations": categories.get("process", []),
                "anti_debug_detections": categories.get("anti_debug", []),
                "crypto_operations": categories.get("crypto", []),
            },
        )

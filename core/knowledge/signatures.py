"""Known patterns, suspicious APIs, and crypto constants for analysis."""

# Windows API categories — used to classify imports and flag suspicious behavior
SUSPICIOUS_API_CATEGORIES: dict[str, list[str]] = {
    "network": [
        "WSAStartup", "WSACleanup", "socket", "connect", "send", "recv",
        "bind", "listen", "accept", "gethostbyname", "getaddrinfo",
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetConnectA", "InternetReadFile",
        "HttpOpenRequestA", "HttpSendRequestA",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    ],
    "file": [
        "CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
        "DeleteFileA", "DeleteFileW", "CopyFileA", "CopyFileW",
        "MoveFileA", "MoveFileW", "GetTempPathA", "GetTempFileNameA",
        "FindFirstFileA", "FindNextFileA",
    ],
    "process": [
        "CreateProcessA", "CreateProcessW", "OpenProcess", "TerminateProcess",
        "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx",
        "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
        "ResumeThread", "SuspendThread",
        "ShellExecuteA", "ShellExecuteW", "WinExec",
        "NtCreateThreadEx",
    ],
    "crypto": [
        "CryptAcquireContextA", "CryptCreateHash", "CryptHashData",
        "CryptDeriveKey", "CryptEncrypt", "CryptDecrypt",
        "CryptGenKey", "CryptImportKey", "CryptExportKey",
        "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
        "BCryptGenerateSymmetricKey",
    ],
    "registry": [
        "RegOpenKeyExA", "RegOpenKeyExW",
        "RegSetValueExA", "RegSetValueExW",
        "RegCreateKeyExA", "RegCreateKeyExW",
        "RegDeleteKeyA", "RegDeleteValueA",
        "RegQueryValueExA", "RegQueryValueExW",
    ],
    "anti_debug": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugStringA", "OutputDebugStringW",
        "GetTickCount", "QueryPerformanceCounter",
        "CloseHandle",  # used as anti-debug trick with invalid handle
    ],
    "injection": [
        "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        "NtMapViewOfSection", "NtUnmapViewOfSection",
        "QueueUserAPC", "NtQueueApcThread",
        "SetWindowsHookExA", "SetWindowsHookExW",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW",
        "CreateServiceA", "CreateServiceW",
        "StartServiceA",
    ],
    "evasion": [
        "SleepEx", "NtDelayExecution",
        "GetSystemTime", "GetLocalTime",
        "GetComputerNameA", "GetUserNameA",
        "GetModuleHandleA",  # used to check for sandbox DLLs
    ],
}

# Flatten for quick lookup: API name -> category
API_TO_CATEGORY: dict[str, str] = {}
for cat, apis in SUSPICIOUS_API_CATEGORIES.items():
    for api in apis:
        API_TO_CATEGORY[api] = cat

# MITRE ATT&CK mapping for API categories
CATEGORY_TO_MITRE: dict[str, list[str]] = {
    "network": ["T1071"],       # Application Layer Protocol
    "process": ["T1055"],       # Process Injection
    "injection": ["T1055"],     # Process Injection
    "crypto": ["T1027"],        # Obfuscated Files
    "anti_debug": ["T1622"],    # Debugger Evasion
    "persistence": ["T1547"],   # Boot/Logon Autostart
    "evasion": ["T1497"],       # Virtualization/Sandbox Evasion
    "registry": ["T1112"],      # Modify Registry
}

# Known crypto constants (for detection in binary data)
CRYPTO_CONSTANTS: dict[str, bytes] = {
    "AES_SBOX": bytes([
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    ]),
    "AES_RCON": bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]),
    "SHA256_INIT": bytes([
        0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85,
        0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A,
    ]),
    "MD5_INIT": bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]),
    "RSA_MAGIC": b"RSA1",
    "BASE64_TABLE": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
}

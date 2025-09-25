import ctypes
from ctypes import wintypes

# === SID STRUCTURE DEFINITION ===
class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_byte * 6)]

class SID(ctypes.Structure):
    _fields_ = [
        ("Revision", ctypes.c_byte),
        ("SubAuthorityCount", ctypes.c_byte),
        ("IdentifierAuthority", SID_IDENTIFIER_AUTHORITY),
        ("SubAuthority", wintypes.DWORD * 1)
    ]

class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [("Label", ctypes.POINTER(SID))]

# === INITIALIZATION ===
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)

# === CONSTANTS ===
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
TOKEN_QUERY = 0x0008
TokenIntegrityLevel = 25

# === FUNCTION DEFINITIONS ===
GetCurrentProcessId = kernel32.GetCurrentProcessId
GetCurrentProcessId.argtypes = ()
GetCurrentProcessId.restype = wintypes.DWORD

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

OpenProcessToken = advapi32.OpenProcessToken
OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
OpenProcessToken.restype = wintypes.BOOL

GetTokenInformation = advapi32.GetTokenInformation
GetTokenInformation.argtypes = (wintypes.HANDLE, ctypes.c_uint, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD))
GetTokenInformation.restype = wintypes.BOOL

GetSidSubAuthorityCount = advapi32.GetSidSubAuthorityCount
GetSidSubAuthorityCount.argtypes = (ctypes.POINTER(SID),)
GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)

GetSidSubAuthority = advapi32.GetSidSubAuthority
GetSidSubAuthority.argtypes = (ctypes.POINTER(SID), ctypes.c_ubyte)
GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = (wintypes.HANDLE,)
CloseHandle.restype = wintypes.BOOL

# === MAIN EXECUTION ===
print("=== Windows Integrity Level Extraction ===")

# 1. Get our PID
my_pid = GetCurrentProcessId()
print(f"Our PID: {my_pid}")

# 2. Get process handle
process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, my_pid)
if process_handle == 0:
    error = ctypes.get_last_error()
    print(f"OpenProcess FAILED. Error: {error}")
    exit(1)

print(f"Process handle obtained: {process_handle}")

# 3. Get token handle
token_handle = wintypes.HANDLE()
success = OpenProcessToken(process_handle, TOKEN_QUERY, ctypes.byref(token_handle))

if not success:
    error = ctypes.get_last_error()
    print(f"OpenProcessToken FAILED. Error: {error}")
    CloseHandle(process_handle)
    exit(1)

print(f"Token handle obtained: {token_handle.value}")

# 4. Get token information - WITH DEBUGGING
print("Step 4: Getting required buffer size...")
return_length = wintypes.DWORD()
success = GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, ctypes.byref(return_length))

print(f"First call success: {success}")
print(f"Return length: {return_length.value}")
if not success:
    error = ctypes.get_last_error()
    print(f"First call error: {error}")

if return_length.value == 0:
    print("Failed to get buffer size - stopping.")
    CloseHandle(token_handle)
    CloseHandle(process_handle)
    exit(1)

print(f"Step 5: Creating buffer of size {return_length.value}...")
buffer = (ctypes.c_byte * return_length.value)()
success = GetTokenInformation(token_handle, TokenIntegrityLevel, buffer, return_length.value, ctypes.byref(return_length))

print(f"Second call success: {success}")
if not success:
    error = ctypes.get_last_error()
    print(f"GetTokenInformation failed with error code: {error}")
else:
    print("GetTokenInformation succeeded! Attempting to parse...")
    
    # Parse the structure
    token_info = ctypes.cast(ctypes.pointer(buffer), ctypes.POINTER(TOKEN_MANDATORY_LABEL)).contents
    
    # Extract integrity level from the SID
    sub_authority_count = GetSidSubAuthorityCount(token_info.Label)[0]
    integrity_level = GetSidSubAuthority(token_info.Label, sub_authority_count - 1)[0]
    
    print(f"Raw Integrity Level: {integrity_level}")
    
    # Map to human-readable values
    levels = {
        0x0000: "Untrusted",
        0x1000: "Low", 
        0x2000: "Medium",
        0x3000: "High",
        0x4000: "System"
    }
    print(f"Integrity Level: {levels.get(integrity_level, 'Unknown')}")

# Cleanup
CloseHandle(token_handle)
CloseHandle(process_handle)
print("Done.")


{
  "process_id": 1234,
  "process_handle": "0x00000048",
  "token_handle": "0x0000007C",
  "integrity_level": {
    "raw_value": 8192,
    "human_readable": "High",
    "level_mapping": {
      "0x0000": "Untrusted",
      "0x1000": "Low", 
      "0x2000": "Medium",
      "0x3000": "High",
      "0x4000": "System"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "status": "success",
  "source_script": "02_ArcanumI_week2_process_scry.py"
}
import ctypes
from ctypes.wintypes import *

PVOID = ctypes.c_void_p
ULONG_PTR = ctypes.POINTER(ULONG)
SIZE_T = UINT
NULL = 0


class ProcessAccess(object):
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    SYNCHRONIZE = 0x00100000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000

    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SUSPEND_RESUME = 0x0800
    PROCESS_TERMINATE = 0x0001
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_ALL_ACCESS = (PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE |
                          PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
                          PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME |
                          PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ |
                          PROCESS_VM_WRITE | SYNCHRONIZE)


class SnapshotFlag(object):
    TH32CS_INHERIT = 0x80000000
    TH32CS_SNAPHEAPLIST = 0x00000001
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    TH32CS_SNAPPROCESS = 0x00000002
    TH32CS_SNAPTHREAD = 0x00000004
    TH32CS_SNAPALL = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPMODULE |
                      TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', ULONG_PTR),
                ('th32ModuleID', DWORD),
                ('cntThread', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG),
                ('dwFlags', DWORD),
                ('szExeFile', (WCHAR * MAX_PATH))]


class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
    _fields_ = [('BaseAddress', PVOID),
                ('AllocationBase', PVOID),
                ('AllocationProtect', DWORD),
                ('RegionSize', DWORD),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD)]

class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_ulonglong),
                ('AllocationBase', ctypes.c_ulonglong),
                ('AllocationProtect', DWORD),
                ('__alignment1', DWORD),
                ('RegionSize', ctypes.c_ulonglong),
                ('State', DWORD),
                ('Protect', DWORD),
                ('Type', DWORD),
                ('__alignment2', DWORD)]


PMEMORY_BASIC_INFORMATION = ctypes.POINTER(MEMORY_BASIC_INFORMATION32)
PMEMORY_BASIC_INFORMATION32 = PMEMORY_BASIC_INFORMATION

PMEMORY_BASIC_INFORMATION64 = ctypes.POINTER(MEMORY_BASIC_INFORMATION64)


class MemoryState(object):
    MEM_COMMIT = 0x1000
    MEM_FREE = 0x10000
    MEM_RESERVE = 0x2000


MAX_MODULE_NAME32 = 256


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', DWORD),
                ('th32ModuleID', DWORD),
                ('th32ProcessID', DWORD),
                ('GlblcntUsage', DWORD),
                ('ProccntUsage', DWORD),
                ('modBaseAddr', PBYTE),
                ('modBaseSize', DWORD),
                ('hModule', HMODULE),
                ('szModule', (CHAR * MAX_MODULE_NAME32)),
                ('szExePath', (CHAR * MAX_PATH))]


class AllocationType(object):
    MEM_COMMIT = 0x00001000
    MEM_RESERVE = 0x00002000
    MEM_RESET = 0x00080000
    MEM_RESET_UNDO = 0x1000000
    MEM_LARGE_PAGES = 0x20000000
    MEM_PHYSICAL = 0x00400000
    MEM_TOP_DOWN = 0x00100000


class MemoryProtection(object):
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_WRITECOPY = 0x08
    PAGE_TARGETS_INVALID = 0x40000000
    PAGE_TARGETS_NO_UPDATE = 0x40000000
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_WRITECOMBINE = 0x400


class FreeType(object):
    MEM_COALESCE_PLACEHOLDERS = 0x00000001
    MEM_PRESERVE_PLACEHOLDER = 0x00000002
    MEM_DECOMMIT = 0x4000
    MEM_RELEASE = 0x8000


class ImageFile(object):
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0
    IMAGE_FILE_MACHINE_TARGET_HOST = 0x0001
    IMAGE_FILE_MACHINE_I386 = 0x014c
    IMAGE_FILE_MACHINE_R3000 = 0x0162
    IMAGE_FILE_MACHINE_R4000 = 0x0166
    IMAGE_FILE_MACHINE_R10000 = 0x0168
    IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169
    IMAGE_FILE_MACHINE_ALPHA = 0x0184
    IMAGE_FILE_MACHINE_SH3 = 0x01a2
    IMAGE_FILE_MACHINE_SH3DSP = 0x01a3
    IMAGE_FILE_MACHINE_SH3E = 0x01a4
    IMAGE_FILE_MACHINE_SH4 = 0x01a6
    IMAGE_FILE_MACHINE_SH5 = 0x01a8
    IMAGE_FILE_MACHINE_ARM = 0x01c0
    IMAGE_FILE_MACHINE_THUMB = 0x01c2
    IMAGE_FILE_MACHINE_ARMNT = 0x01c4
    IMAGE_FILE_MACHINE_AM33 = 0x01d3
    IMAGE_FILE_MACHINE_POWERPC = 0x01F0
    IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1
    IMAGE_FILE_MACHINE_IA64 = 0x0200
    IMAGE_FILE_MACHINE_MIPS16 = 0x0266
    IMAGE_FILE_MACHINE_ALPHA64 = 0x0284
    IMAGE_FILE_MACHINE_MIPSFPU = 0x0366
    IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466
    IMAGE_FILE_MACHINE_AXP64 = 0x0284
    IMAGE_FILE_MACHINE_TRICORE = 0x0520
    IMAGE_FILE_MACHINE_CEF = 0x0CEF
    IMAGE_FILE_MACHINE_EBC = 0x0EBC
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_M32R = 0x9041
    IMAGE_FILE_MACHINE_ARM64 = 0xAA64


Kernel32 = ctypes.windll.kernel32
Kernel32.VirtualAllocEx.restype = LPVOID # Wrong address given (the high part of the address was missing)

NTDLL = ctypes.WinDLL("ntdll.dll")
PSAPI = ctypes.windll.psapi

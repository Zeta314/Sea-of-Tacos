import functools
import struct

from .natives import *
from .exceptions import *


def status_checked(func):
    """ Decorator that checks if process is open before executing method """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        instance = args[0]

        if not isinstance(instance, Process):
            raise RuntimeError("Class is not a process.")

        if not instance.is_open:
            raise ProcessException("Process not open.")

        return func(*args, **kwargs)
    return wrapper


class Process(object):
    def __init__(self, dwProcessID: int):
        self.__dwProcessID = DWORD(dwProcessID)
        self.__handle = None

    @property
    def processID(self) -> int:
        """ Get the process ID """

        return struct.unpack("<L", self.__dwProcessID)[0]

    @property
    def is_open(self) -> bool:
        """ Check if we got a process handle open """

        return not (self.__handle == NULL or self.__handle is None)

    @property
    def handle(self) -> int:
        """ Get the process handle """

        return self.__handle

    @property
    @status_checked
    def is_64bit(self) -> bool:
        process_machine = USHORT()
        native_machine = USHORT()

        if not Kernel32.IsWow64Process2(self.__handle, ctypes.byref(process_machine), ctypes.byref(native_machine)):
            raise ProcessException("Failed to get process bits.")

        if process_machine == ImageFile.IMAGE_FILE_MACHINE_UNKNOWN:
            if (native_machine == ImageFile.IMAGE_FILE_MACHINE_IA64 or
                native_machine == ImageFile.IMAGE_FILE_MACHINE_AMD64 or
                    native_machine == ImageFile.IMAGE_FILE_MACHINE_ARM64):

                return True

            if (native_machine == ImageFile.IMAGE_FILE_MACHINE_I386 or
                    native_machine == ImageFile.IMAGE_FILE_MACHINE_ARM):
                return False

        else:
            return True

        return is64Bit

    @staticmethod
    def by_name(name: str):
        """ Create a process instance giving the process name """

        snapshot = Kernel32.CreateToolhelp32Snapshot(
            SnapshotFlag.TH32CS_SNAPALL, NULL)
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)

        if (not Kernel32.Process32FirstW(snapshot, ctypes.pointer(entry))):
            raise ProcessException("Failed to enumerate processes.")

        process_id = None
        while process_id is None:
            if entry.szExeFile == name:
                process_id = entry.th32ProcessID

            if not Kernel32.Process32NextW(snapshot, ctypes.pointer(entry)):
                break

        if process_id is None:
            raise ProcessException("Process not found.")

        return Process(process_id)

    def open(self, dwDesiredAccess: ProcessAccess = ProcessAccess.PROCESS_ALL_ACCESS, bInheritHandle: bool = False):
        """ Get the process handle with the given access """

        self.__handle = Kernel32.OpenProcess(
            dwDesiredAccess, bInheritHandle, self.__dwProcessID)

        if not self.is_open:
            raise ProcessException("Failed to get process handle.")

    @status_checked
    def close(self):
        """ Close the process handle """

        if not Kernel32.CloseHandle(self.__handle):
            raise ProcessException("Failed to close process handle.")

        self.__handle = None

    @status_checked
    def suspend(self):
        """ Suspend the process execution """

        NTDLL.NtSuspendProcess(self.__handle)

    @status_checked
    def resume(self):
        """ Resume the process execution """

        NTDLL.NtResumeProcess(self.__handle)

    @status_checked
    def terminate(self, exit_code: int = 0):
        """ Terminate the process execution returning the given code """

        if not Kernel32.TerminateProcess(self.__handle, exit_code):
            raise ProcessException("Failed to terminate process.")

    @status_checked
    def module_address(self, name: str) -> int:
        """ Get the given module base address """

        snapshot = Kernel32.CreateToolhelp32Snapshot(
            SnapshotFlag.TH32CS_SNAPMODULE, self.__dwProcessID)

        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        if not Kernel32.Module32First(snapshot, ctypes.pointer(entry)):
            Kernel32.CloseHandle(snapshot)
            raise ProcessException("Failed to get modules list.")

        while True:
            if entry.szModule == name.encode():
                Kernel32.CloseHandle(snapshot)
                return struct.unpack("<Q", entry.modBaseAddr)[0]

            if not Kernel32.Module32Next(snapshot, ctypes.pointer(entry)):
                break

        Kernel32.CloseHandle(snapshot)
        raise ProcessException("Module base address not found.")

    @status_checked
    def module_size(self, name: str) -> int:
        """ Get the given module base size """

        snapshot = Kernel32.CreateToolhelp32Snapshot(
            SnapshotFlag.TH32CS_SNAPMODULE, self.__dwProcessID)

        entry = MODULEENTRY32()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32)

        if not Kernel32.Module32First(snapshot, ctypes.pointer(entry)):
            Kernel32.CloseHandle(snapshot)
            raise ProcessException("Failed to get modules list.")

        while True:
            if entry.szModule == name.encode():
                Kernel32.CloseHandle(snapshot)
                return entry.modBaseSize

            if not Kernel32.Module32Next(snapshot, ctypes.pointer(entry)):
                break

        Kernel32.CloseHandle(snapshot)
        raise ProcessException("Module base size not found.")

    @status_checked
    def create_thread(self, exec_address: int, parameters: int = NULL):
        """ Create a thread that executes memory at the given address """

        handle = Kernel32.CreateRemoteThread(self.__handle, NULL, 0, LPCVOID(
            exec_address), LPVOID(parameters), NULL, NULL)

        if handle == NULL:
            raise ProcessException("Failed to create remote thread.")

        return handle

    # INJECTION STUFF

    @status_checked
    def inject_shellcode(self, shellcode: bytes, run: bool = False) -> int:
        """ Inject the given shellcode and return the memory address it's allocated at """

        memory_addr = self.memory.allocate(
            len(shellcode), MemoryProtection.PAGE_EXECUTE_READWRITE)

        self.memory.write_memory(memory_addr, shellcode)
        self.memory.protect(memory_addr, len(shellcode),
                            MemoryProtection.PAGE_EXECUTE)

        if run:
            self.create_thread(memory_addr)

        return memory_addr

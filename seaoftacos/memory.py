import functools
import struct
import re
import threading

from .process import *
from .exceptions import *
from .natives import *


def status_checked(func):
    """ Decorator that checks if process is open before executing method """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        instance = args[0]

        if not isinstance(instance, Memory):
            raise RuntimeError("Class is not a process.")

        if not instance.process.is_open:
            raise ProcessException("Process not open.")

        return func(*args, **kwargs)
    return wrapper


class PatternTools(object):
    @staticmethod
    def check_pattern(data: bytes, mask: str, pattern: bytes):
        if len(pattern) > len(data):
            return False

        for i in range(len(pattern)):
            if mask[i] == '?':
                continue

            if pattern[i].to_bytes(1, 'little') != data[i]:
                return False

        return True

    @staticmethod
    def compile_pattern(pattern: str) -> tuple:
        mask = re.sub(r"([0-9A-Fa-f]{2})", "X", pattern)
        mask = re.sub(r"\?{2}", "?", mask)
        mask = re.sub(r" ", "", mask)

        pattern = re.sub(r"\?", "0", pattern)
        pattern = bytes.fromhex(pattern)

        return mask, pattern


class Memory(object):
    def __init__(self, process: Process):
        self.__process = process

    @property
    def process(self):
        """ Get the parent process object """

        return self.__process

    @status_checked
    def read_memory(self, address: int, size: int) -> bytes:
        """ Read from the process memory at the given address """

        buffer = ctypes.create_string_buffer(size)

        if not Kernel32.ReadProcessMemory(self.__process.handle, LPCVOID(address), buffer, size, NULL):
            raise MemoryException("Failed to read process memory.")

        return buffer.raw

    def __read_type(self, address: int, format: str):
        """ A tool just to make submethod creation easier """

        format = f"<{format}"
        return struct.unpack(format, self.read_memory(address, struct.calcsize(format)))[0]

    def read_short(self, address: int) -> int:
        return self.__read_type(address, "h")

    def read_int(self, address: int) -> int:
        return self.__read_type(address, "i")

    def read_long(self, address: int) -> int:
        return self.__read_type(address, "q")

    def read_string(self, address: int, length: int = None) -> str:
        output = b''

        while True:
            char = self.read_memory(address + len(output), 1)

            if char == b'\x00' or (length is not None and len(output) >= length):
                break

            output += char

        return output.decode()

    @status_checked
    def write_memory(self, address: int, data: bytes):
        """ Write the given data at the given address into the process memory """

        buffer = ctypes.create_string_buffer(data)

        if not Kernel32.WriteProcessMemory(self.__process.handle,
                                           LPVOID(address),
                                           buffer,
                                           len(data), NULL):
            raise MemoryException("Failed to write process memory.")

    def __write_type(self, address: int, format: str, data: bytes):
        """ A tool just to make submethod creation easier """

        format = f"<{format}"
        self.write_memory(address, struct.pack(format, data))

    def write_short(self, address: int, data: int):
        self.__write_type(address, "h", data)

    def write_int(self, address: int, data: int):
        self.__write_type(address, "i", data)

    def write_long(self, address: int, data: int):
        self.__write_type(address, "q", data)

    def write_string(self, address: int, string: str):
        self.__write_type(
            address, f"{len(string) + 1}s", string.encode() + b'\x00')

    # PATTERN SCANNING STUFF

    def __pattern_scan(self, start_address: int, size: int, mask: str, pattern: bytes) -> list:
        addresses = []
        buffer = ctypes.create_string_buffer(size)

        if not Kernel32.ReadProcessMemory(self.__process.handle,
                                          LPVOID(start_address),
                                          buffer, SIZE_T(size), NULL):
            raise MemoryException("Failed to read process memory.")

        for i in range(size):
            new_buffer = (CHAR * (size - i)).from_buffer(buffer, i)

            if PatternTools.check_pattern(new_buffer, mask, pattern):
                addresses.append(start_address + i)

            del new_buffer

        if not addresses:
            raise MemoryException("Failed to find pattern.")

        return addresses

    @status_checked
    def pattern_scan(self, start_address: int, size: int, pattern: str) -> list:
        """ 
            Scan for the given pattern in the given memory region.
            Pattern example: 48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 74 06 48 8B 49 70
        """

        mask, pattern = PatternTools.compile_pattern(pattern)
        return self.__pattern_scan(start_address, size, mask, pattern)

    # ALLOCATION STUFF

    @status_checked
    def allocate(self, size: int, protection: MemoryProtection) -> int:
        """ Allocate memory into the given process """

        address = Kernel32.VirtualAllocEx(
            self.__process.handle, NULL, size, AllocationType.MEM_COMMIT, protection)

        if address is None or address == NULL:
            raise MemoryException("Failed to allocate memory.")

        return address

    @status_checked
    def protect(self, address: int, size: int, protection: MemoryProtection):
        """ VirtualProtectEx wrapper """

        old_protection = DWORD()
        if not Kernel32.VirtualProtectEx(self.__process.handle, LPVOID(address), size, DWORD(protection), ctypes.pointer(old_protection)):
            raise MemoryException("Failed to protect memory.")

    @status_checked
    def free(self, address: int):
        """ Free the memory at the given address """

        if not Kernel32.VirtualFreeEx(self.__process.handle, LPVOID(address), NULL, FreeType.MEM_RELEASE):
            raise MemoryException("Failed to free memory.")

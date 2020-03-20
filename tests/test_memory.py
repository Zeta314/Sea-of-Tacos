import unittest
import subprocess
import re
import sys
import os

from seaoftacos import *


class TestMemory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.maxsize > 2**32:
            cls.__procname = "tester_x64.exe"
        else:
            cls.__procname = "tester_x86.exe"

        cls.__process = subprocess.Popen(
            f"tests/{cls.__procname}", stdout=subprocess.PIPE)

        cls.__addresses = []
        for line in [cls.__process.stdout.readline() for _ in range(4)]:
            cls.__addresses.append(int(line, 16))

    @classmethod
    def tearDownClass(cls):
        cls.__process.terminate()
        cls.__process.wait()

    def test_platform(self):
        """ Test if the current platform is Windows """

        self.assertEqual(os.name, "nt")

    def test_read(self):
        """ Test the read methods """

        try:
            proc = Process(self.__process.pid)
            proc.open()

        except ProcessException:
            self.fail("Failed to open process.")

        mem = Memory(proc)
        self.assertEqual(mem.read_short(self.__addresses[0]), 1234)
        self.assertEqual(mem.read_int(self.__addresses[1]), 5678)
        self.assertEqual(mem.read_long(self.__addresses[2]), 9123)
        self.assertEqual(mem.read_string(
            self.__addresses[3]), "TESTING # 12345")

        proc.close()

    def test_read(self):
        """ Test the read methods """

        try:
            proc = Process(self.__process.pid)
            proc.open()

        except ProcessException:
            self.fail("Failed to open process.")

        mem = Memory(proc)
        self.assertEqual(mem.read_short(self.__addresses[0]), 1234)
        self.assertEqual(mem.read_int(self.__addresses[1]), 5678)
        self.assertEqual(mem.read_long(self.__addresses[2]), 9123)
        self.assertEqual(mem.read_string(
            self.__addresses[3]), "TESTING # 12345")

        proc.close()

    def test_write(self):
        """ Test the write methods """

        try:
            proc = Process(self.__process.pid)
            proc.open()

        except ProcessException:
            self.fail("Failed to open process.")

        mem = Memory(proc)

        mem.write_short(self.__addresses[0], 4321)
        self.assertEqual(mem.read_short(self.__addresses[0]), 4321)

        mem.write_int(self.__addresses[1], 8765)
        self.assertEqual(mem.read_int(self.__addresses[1]), 8765)

        mem.write_long(self.__addresses[2], 3219)
        self.assertEqual(mem.read_long(self.__addresses[2]), 3219)

        mem.write_string(self.__addresses[3], "54321 # GNITSET")
        self.assertEqual(mem.read_string(
            self.__addresses[3]), "54321 # GNITSET")

        proc.close()

    def test_alloc_misc(self):
        """ Test the alloc, protect and free methods """

        try:
            proc = Process(self.__process.pid)
            proc.open()
        except ProcessException:
            self.fail("Failed to open process.")

        mem = Memory(proc)

        mem_ptr = mem.allocate(1024, MemoryProtection.PAGE_READWRITE)

        mem.write_string(mem_ptr, "TEST 12345678")
        mem.protect(mem_ptr, 1024, MemoryProtection.PAGE_READONLY)

        try:
            mem.write_string(mem_ptr, "TEST 87654321") # Expected failure on this since memory is protected
            self.fail("Memory is not protected.")
        except MemoryException:
            pass

        mem.free(mem_ptr)
        proc.close()

    def test_pattern_scan(self):
        """ Test the pattern scan feature """

        try:
            proc = Process(self.__process.pid)
            proc.open()
        except ProcessException:
            self.fail("Failed to open process.")

        mem = Memory(proc)
        
        mem_ptr = mem.allocate(1024, MemoryProtection.PAGE_READWRITE)

        mem.write_memory(mem_ptr, b"\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43")

        base_addr = proc.module_address(f"{self.__procname}")
        base_size = proc.module_size(f"{self.__procname}")

        pattern_ptr = mem.pattern_scan(mem_ptr - 4096, 8192, "41 41 41 41 42 42 42 42 43 43 43 43")[0]

        if pattern_ptr != mem_ptr:
            self.fail("Wrong address found.")

        proc.close()


if __name__ == "__main__":
    unittest.main()

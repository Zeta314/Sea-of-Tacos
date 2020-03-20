import unittest
import subprocess
import re
import sys
import os

from seaoftacos import *


class TestProcess(unittest.TestCase):
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

    def test_byname(self):
        """ Test getting process by name """

        try:
            Process.by_name(f"{self.__procname}")
        except ProcessException:
            self.fail("Getting process by name failed.")

    def test_open(self):
        """ Test opening process by PID """

        try:
            proc = Process(self.__process.pid)
            proc.open()
        except ProcessException:
            self.fail("Opening process by PID failed.")

    def test_open_byname(self):
        """ Test opening process by name """

        try:
            proc = Process.by_name(f"{self.__procname}")
            proc.open()
        except ProcessException:
            self.fail("Opening process by name failed.")

    def test_close(self):
        """ Test closing process handle """

        try:
            proc = Process(self.__process.pid)
            proc.open()
            proc.close()
        except ProcessException:
            self.fail("Closing process handle failed.")

    @unittest.expectedFailure
    def test_close_notopen(self):
        """ Try closing process without opening it """

        proc = Process(self.__process.pid)
        proc.close()

    def test_isopen(self):
        """ Test the is_open flag """

        proc = Process(self.__process.pid)
        proc.open()
        self.assertTrue(proc.is_open)
        proc.close()

    def test_is_64bit(self):
        """ Test the is_64bit flag """

        proc = Process(self.__process.pid)
        proc.open()
        self.assertEqual(proc.is_64bit, sys.maxsize > 2**32)
        proc.close()

    def test_terminate(self):
        """ Test terminating the process """
        """ THIS MUST BE THE LAST TEST """

        proc = Process(self.__process.pid)
        proc.open()
        proc.terminate(162)
        self.__process.wait()
        self.assertEqual(self.__process.returncode, 162)
        proc.close()


if __name__ == "__main__":
    unittest.main()

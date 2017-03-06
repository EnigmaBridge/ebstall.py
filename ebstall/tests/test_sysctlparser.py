#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ebstall.sysctlparser import SysctlConfig
import unittest

__author__ = 'dusanklinec'


test1 = """net.ipv4.ip_forward = 1
# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536   # hello-comment test
#kernel.msgmax = 65536"""


class SysctlParserTest(unittest.TestCase):
    """Simple test from the readme"""

    def __init__(self, *args, **kwargs):
        super(SysctlParserTest, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test1(self):
        parser = SysctlConfig(static_config=test1)
        parser.load()
        data = parser.config_data

        # Simple parser test
        self.assertEqual(len(data), 4, 'Number of parsed lines does not match')

        self.assertEqual(data[0].ltype, 3, 'Parsed command has invalid type')
        self.assertEqual(data[0].cmd, 'net.ipv4.ip_forward', 'Parsed command is invalid')
        self.assertEqual(data[0].params, '1', 'Parsed command value is invalid')
        self.assertEqual(data[0].comment, None, 'Invalid parsed comment, should be null')

        self.assertEqual(data[1].ltype, 1, 'Second line should be a comment')
        self.assertEqual(data[1].cmd, None)
        self.assertEqual(data[1].params, None)
        self.assertEqual(data[1].comment, None)

        self.assertEqual(data[2].ltype, 3)
        self.assertEqual(data[2].cmd, 'kernel.msgmax')
        self.assertEqual(data[2].params, '65536')
        self.assertEqual(data[2].comment, '# hello-comment test')

        self.assertEqual(data[3].ltype, 2)
        self.assertEqual(data[3].cmd, 'kernel.msgmax')
        self.assertEqual(data[3].params, '65536')
        self.assertEqual(data[3].comment, None)

    def test1_change(self):
        parser = SysctlConfig(static_config=test1)
        parser.load()
        parser.set_config_value('net.ipv4.ip_forward', '0')
        parser.set_config_value('net.ipv6.ip_forward', '0')

        ctr = 0
        ctr_comm = 0
        for rec in parser.config_data:
            if rec.ltype == 3 and rec.cmd == 'net.ipv4.ip_forward':
                ctr += 1

                self.assertEqual(rec.params, '0', 'Invalid command value after change')
            if rec.ltype == 2 and rec.cmd == 'net.ipv4.ip_forward':
                ctr_comm += 1

        self.assertEqual(ctr, 1, 'Has to be exactly one command with the given value')
        self.assertLessEqual(ctr_comm, 1, 'Commented out value should be max 1')

        # ipv6 should be there as well
        ctr = 0
        ctr_comm = 0
        for rec in parser.config_data:
            if rec.ltype == 3 and rec.cmd == 'net.ipv6.ip_forward':
                ctr += 1

                self.assertEqual(rec.params, '0', 'Invalid command value after change')
            if rec.ltype == 2 and rec.cmd == 'net.ipv6.ip_forward':
                ctr_comm += 1

        self.assertEqual(ctr, 1, 'Has to be exactly one command with the given value')
        self.assertLessEqual(ctr_comm, 0)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover



#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ebstall.openvpn import OpenVpnConfig
import unittest

__author__ = 'dusanklinec'


test1 = """client-to-client
server 10.8.0.0 255.255.255.0
;server 10.7.0.0 255.255.255.0
key server.key  # This file should be kept secret
;key server.key  # This file should be kept secret
# test"""

test2 = """;persist-tun"""

test3 = """persist-tun"""

test4 = """;key server.key  # This file should be kept secret"""

test5 = """push alpha
push beta
push gamma
push delta
push zetta"""

test6 = """remote [(${vpn_hostname})] 1194
resolv-retry infinite"""

test7 = """remote [(${vpn_hostname})] 1194
resolv-retry infinite
<ca>
line1
line2
line3
</ca>
persist-tun"""


class OpenVpnParserTest(unittest.TestCase):
    """Simple test from the readme"""

    def __init__(self, *args, **kwargs):
        super(OpenVpnParserTest, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test1(self):
        parser = OpenVpnConfig(static_config=test1)
        parser.load()
        data = parser.config_data

        # Simple parser test
        self.assertEqual(len(data), 6, 'Number of parsed lines does not match')

        self.assertEqual(data[0].ltype, 3, 'Parsed command has invalid type')
        self.assertEqual(data[0].cmd, 'client-to-client')
        self.assertEqual(data[0].params, None)
        self.assertEqual(data[0].comment, None)

        self.assertEqual(data[1].ltype, 3)
        self.assertEqual(data[1].cmd, 'server')
        self.assertEqual(data[1].params, '10.8.0.0 255.255.255.0')
        self.assertEqual(data[1].comment, None)

        self.assertEqual(data[2].ltype, 2)
        self.assertEqual(data[2].cmd, 'server')
        self.assertEqual(data[2].params, '10.7.0.0 255.255.255.0')
        self.assertEqual(data[2].comment, None)

        self.assertEqual(data[3].ltype, 3)
        self.assertEqual(data[3].cmd, 'key')
        self.assertEqual(data[3].params, 'server.key')
        self.assertEqual(data[3].comment, '# This file should be kept secret')

        self.assertEqual(data[4].ltype, 2)
        self.assertEqual(data[4].cmd, 'key')
        self.assertEqual(data[4].params, 'server.key')
        self.assertEqual(data[4].comment, '# This file should be kept secret')

        self.assertEqual(data[5].ltype, 1)

        test1x = parser.dump()
        parser2 = OpenVpnConfig(static_config=test1x)
        parser2.load()
        data2 = parser.config_data
        self.assertEqual(data2, data, 'Parser did not return the same data')

    def test1_remove_single(self):
        parser = OpenVpnConfig(static_config=test1)
        parser.load()
        parser.set_config_value('client-to-client', remove=True)

        ctr_comm = 0
        for rec in parser.config_data:
            if rec.cmd == 'client-to-client':
                self.assertEqual(rec.ltype, 2, 'Directive is still active')

            if rec.ltype == 2 and rec.cmd == 'client-to-client':
                ctr_comm += 1

        self.assertLessEqual(ctr_comm, 1, 'Commented out value should be max 1')

    def test1_remove_key(self):
        parser = OpenVpnConfig(static_config=test1)
        parser.load()
        parser.set_config_value('key', remove=True)
        ctr_comm = 0
        for rec in parser.config_data:
            if rec.cmd == 'key':
                self.assertEqual(rec.ltype, 2, 'Directive is still active')

            if rec.ltype == 2 and rec.cmd == 'key':
                ctr_comm += 1

        self.assertLessEqual(ctr_comm, 2, 'Commented out value should be max 2')

    def test2_remove_removed(self):
        parser = OpenVpnConfig(static_config=test2)
        parser.load()
        parser.set_config_value('persist-tun', remove=True)
        data = parser.config_data
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].ltype, 2)

    def test2_add_removed_single(self):
        parser = OpenVpnConfig(static_config=test2)
        parser.load()
        parser.set_config_value('persist-tun')
        data = parser.config_data
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].ltype, 3)

    def test3_add_added(self):
        parser = OpenVpnConfig(static_config=test3)
        parser.load()
        parser.set_config_value('persist-tun')
        data = parser.config_data
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].ltype, 3)

    def test3_remove_added(self):
        parser = OpenVpnConfig(static_config=test3)
        parser.load()
        parser.set_config_value('persist-tun', remove=True)
        data = parser.config_data
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].ltype, 2)

    def test4_add_key(self):
        parser = OpenVpnConfig(static_config=test4)
        parser.load()
        parser.set_config_value('key', 'server.key')
        data = parser.config_data
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0].ltype, 3)

    def test5_push(self):
        parser = OpenVpnConfig(static_config=test5)
        parser.load()

        vals = ['alpha', 'beta', 'delta', 'secret']
        parser.set_config_value('push', vals)

        data = parser.config_data
        self.assertEqual(len(data), 6)

        vals_present = [False] * len(vals)
        for cur in data:
            if cur.ltype == 3:
                self.assertTrue(cur.params in vals)
                vals_present[vals.index(cur.params)] = True

        self.assertEqual(vals_present, [True] * len(vals))

    def test5_push_remove(self):
        parser = OpenVpnConfig(static_config=test5)
        parser.load()

        vals = ['alpha', 'secret']
        parser.set_config_value('push', vals, remove=True)

        data = parser.config_data
        self.assertEqual(len(data), 5)

        vals_present = [False] * len(vals)
        for cur in data:
            if cur.ltype == 3 and cur.params in vals:
                vals_present[vals.index(cur.params)] = True
        self.assertEqual(vals_present, [False] * len(vals))

    def test6(self):
        parser = OpenVpnConfig(static_config=test6)
        parser.load()
        data = parser.config_data
        self.assertEqual(len(data), 2, 'Number of parsed lines does not match')

        self.assertEqual(data[0].ltype, 3)
        self.assertEqual(data[0].cmd, 'remote')

        self.assertEqual(data[1].ltype, 3)
        self.assertEqual(parser.dump(), test6, 'Parser did not return the same data')

    def test7(self):
        parser = OpenVpnConfig(static_config=test7)
        parser.load()
        data = parser.config_data

        self.assertEqual(parser.dump().strip(), test7.strip(), 'Parser did not return the same data')

        testx = parser.dump()
        parser2 = OpenVpnConfig(static_config=testx)
        parser2.load()
        data2 = parser.config_data
        self.assertEqual(data2, data, 'Parser did not return the same data')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover



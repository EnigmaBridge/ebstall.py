#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ebstall.versions as util
import unittest

__author__ = 'dusanklinec'


class VersionTest(unittest.TestCase):
    """Simple test from the readme"""

    def __init__(self, *args, **kwargs):
        super(VersionTest, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_verlen(self):
        self.assertEqual(util.version_len('5.4'), 2)
        self.assertEqual(util.version_len('5'), 1)
        self.assertEqual(util.version_len('5-1'), 1)
        self.assertEqual(util.version_len('5.4.5-1'), 3)

    def test_vercmp(self):
        self.assertEqual(util.version_cmp('5.4', '5.4'), 0)
        self.assertEqual(util.version_cmp('5.4', '5.5'), -1)
        self.assertEqual(util.version_cmp('5.6', '5.5'), 1)

        self.assertEqual(util.version_cmp('5.4', '5.4.3', max_comp=2), 0)
        self.assertEqual(util.version_cmp('5.4', '5.4.3', max_comp=3), -1)

        self.assertEqual(util.version_cmp('5.4.20-4', '5.4.20-4'), 0)
        self.assertEqual(util.version_cmp('5.4.20-4', '5.4.20-5'), -1)
        self.assertEqual(util.version_cmp('5.4.20-4', '5.4.3'), 1)

    def test_trim(self):
        self.assertEqual(util.version_trim('5.4.20-4'), '5.4.20-4')
        self.assertEqual(util.version_trim('5.4.20-4', 2), '5.4')
        self.assertEqual(util.version_trim('5.4.20-4', 1), '5')

    def test_pick_filter(self):
        versions = [
            ('a', '5.3.12'), ('b', '5.3.12'),
            ('a', '5.4.12'), ('b', '5.4.12'),
            ('a', '5.5.12'), ('a', '5.5.12'),
            ('a', '5.6.12'), ('a', '5.6.12'),
            ('a', '7.2'), ('a', '7.2')
        ]

        res = util.version_filter(versions, key=lambda x: x[1], exact_version='5.5')
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0][1], '5.5.12')

        res = util.version_filter(versions, key=lambda x: x[1], exact_version='5.5.12')
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0][1], '5.5.12')

        res = util.version_filter(versions, key=lambda x: x[1], min_version='5.4', max_version='5.99')
        self.assertEqual(len(res), 6)

        res = util.version_pick(versions, key=lambda x: x[1], pick_min=True)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0][1], '5.3.12')
        self.assertEqual(res[1][1], '5.3.12')

        res = util.version_pick(versions, key=lambda x: x[1], pick_max=True)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0][1], '7.2')
        self.assertEqual(res[1][1], '7.2')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover



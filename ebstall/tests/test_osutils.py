#!/usr/bin/env python
# -*- coding: utf-8 -*-
import ebstall.osutil as osutil
import pkg_resources
import unittest


__author__ = 'dusanklinec'


class YumParserTest(unittest.TestCase):
    """Simple test for yum output processing"""

    def __init__(self, *args, **kwargs):
        super(YumParserTest, self).__init__(*args, **kwargs)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _get_res(self, name):
        """
        Loads resource
        :param name: 
        :return: 
        """
        resource_package = __name__
        resource_path = '/'.join(('data', name))
        return pkg_resources.resource_string(resource_package, resource_path)

    def test_yum_update(self):
        output = self._get_res("yum_update_list")
        pkgs = osutil.get_yum_packages_update(output)

        self.assertTrue(len(pkgs) > 5)
        self.assertTrue(len(pkgs) == 41)
        self.assertTrue(len([x for x in pkgs if x.name == 'kernel']) == 1)
        self.assertTrue(len([x for x in pkgs if x.name == 'kernel-headers']) == 1)
        self.assertTrue(len([x for x in pkgs if x.name == 'libidn2']) == 1)
        self.assertTrue(len([x for x in pkgs if x.name == 'vim-common']) == 1)

        kernel_pkg = [x for x in pkgs if x.name == 'kernel'][0]
        self.assertEqual(kernel_pkg.arch, 'x86_64')
        self.assertEqual(str(kernel_pkg.version), '4.9.20-10.30.amzn1')

        vim_pkg = [x for x in pkgs if x.name == 'vim-common'][0]
        self.assertEqual(str(vim_pkg.version), '2:8.0.0503-1.45.amzn1')


if __name__ == "__main__":
    unittest.main()  # pragma: no cover



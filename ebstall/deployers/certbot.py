#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import logging


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class Certbot(object):
    """
    Certbot installation
    """

    def __init__(self, sysconfig=None, audit=None, write_dots=False, *args, **kwargs):
        self.sysconfig = sysconfig
        self.audit = audit
        self.write_dots = write_dots

    #
    # Installation
    #
    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        cmd_exec = 'sudo pip install --upgrade certbot certbot-nginx'
        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dots)


#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import collections
import re
import util
import subprocess
import types
import osutil
import shutil
import pkg_resources


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class DnsMasq(object):
    """
    DNS Masq configuration
    """
    SETTINGS_FILE = '/etc/dnsmasq.conf'

    def __init__(self, sysconfig=None, write_dots=False, audit=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dots = write_dots
        self.vpn_server_ip = '10.8.0.1'
        self.hostname = 'private-space'

    #
    # server.conf reading & modification
    #

    def get_config_file_path(self):
        """
        Returns config file path
        :return: server config file path
        """
        return self.SETTINGS_FILE

    def load_static_config(self):
        """
        Loads static config from the package
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('consts', 'dnsmasq.conf'))
        return pkg_resources.resource_string(resource_package, resource_path)

    #
    # Configuration
    #

    def configure_server(self):
        """
        Perform base server configuration.
        :return: True if file was changed
        """

        tpl = self.load_static_config()
        tpl = tpl.replace('{{ dnsmasq_openvpn_ip }}', self.vpn_server_ip)
        tpl += '\nserver=8.8.8.8'
        tpl += '\nserver=8.8.4.4'
        tpl += '\n'

        # Important in-vpn aliases
        tpl += '\naddress=/%s/%s' % (self.hostname, self.vpn_server_ip)
        tpl += '\naddress=/private-space/%s' % self.vpn_server_ip
        tpl += '\naddress=/private.space/%s' % self.vpn_server_ip
        tpl += '\naddress=/private-dimension/%s' % self.vpn_server_ip
        tpl += '\naddress=/private.dimension/%s' % self.vpn_server_ip
        tpl += '\naddress=/private/%s' % self.vpn_server_ip
        tpl += '\naddress=/space/%s' % self.vpn_server_ip
        tpl += '\naddress=/vpn/%s' % self.vpn_server_ip
        tpl += '\naddress=/pki/%s' % self.vpn_server_ip
        tpl += '\naddress=/enigma/%s' % self.vpn_server_ip
        tpl += '\naddress=/ejbca/%s' % self.vpn_server_ip
        tpl += '\naddress=/admin/%s' % self.vpn_server_ip
        tpl += '\n'

        cpath = self.get_config_file_path()
        fh, backup = util.safe_create_with_backup(cpath, 'w', 0o644)
        with fh:
            fh.write(tpl)
        return True

    #
    # Installation
    #
    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        cmd_exec = 'sudo yum install -y dnsmasq'
        if self.sysconfig.get_packager() == osutil.PKG_APT:
            cmd_exec = 'sudo apt-get install -y dnsmasq'

        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dots)

    def get_svc_map(self):
        """
        Returns service naming for different start systems
        :return:
        """
        return {
            osutil.START_SYSTEMD: 'dnsmasq.service',
            osutil.START_INITD: 'dnsmasq'
        }

    def enable(self):
        """
        Enables service after OS start
        :return:
        """
        return self.sysconfig.enable_svc(self.get_svc_map())

    def switch(self, start=None, stop=None, restart=None):
        """
        Starts/stops/restarts the service
        :param start:
        :param stop:
        :param restart:
        :return:
        """
        return self.sysconfig.switch_svc(self.get_svc_map(), start=start, stop=stop, restart=restart)



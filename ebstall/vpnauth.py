#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import errors
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


class VpnAuth(object):
    """
    VPN Auth server
    """
    CONFIG_FILE = '/etc/supervisord.d/vpnauth.conf'
    DB_USER = 'vpnauth'
    SUPERVISOR_CMD = 'vpnauth'

    def __init__(self, sysconfig=None, audit=None, write_dots=False, supervisord=None, mysql=None, config=None, ovpn=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dost = write_dots
        self.audit = audit
        self.supervisor = supervisord
        self.mysql = mysql
        self.config = config
        self.ejbca = None
        self.ovpn = ovpn

    #
    # Installation
    #

    def configure(self):
        """
        Configures supervisord after manual installation
        :return:
        """
        self.config.vpnauth_enc_password = util.random_password(16)
        self.config.vpnauth_db_password = util.random_password(16)
        self.audit.add_secrets(self.config.vpnauth_enc_password)
        self.audit.add_secrets(self.config.vpnauth_db_password)

        self.config.vpnauth_db = self.ejbca.MYSQL_DB
        self.mysql.create_user(self.DB_USER, self.config.vpnauth_db_password, self.config.vpnauth_db)

    def configure_vpn_server(self):
        """
        Configures VPN server to use VPNAuth event scripts
        :return:
        """
        epiper = self.sysconfig.epiper_path()
        connect = '%s vpnauth-notif --ebstall --event connected' % epiper
        disconnect = '%s vpnauth-notif --ebstall --event disconnected' % epiper
        up = '%s vpnauth-notif --ebstall --event up' % epiper
        down = '%s vpnauth-notif --ebstall --event down' % epiper
        self.ovpn.configure_server_scripts(connect=connect, disconnect=disconnect, up=up, down=down)

    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        cmd_exec = 'sudo pip install vpnauth'
        ret = self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dost)
        if ret != 0:
            raise errors.SetupError('Could not install vpnauth from the pip')

        return 0

    def enable(self):
        """
        Enables service after OS start
        :return:
        """
        with open(self.CONFIG_FILE, 'w') as fh:
            fh.write('[program:%s]\n' % self.SUPERVISOR_CMD)
            fh.write('directory=/tmp\n')
            fh.write('command=%s vpnauth-server --ebstall --dump-stats /usr/share/nginx/html/stats.json\n'
                     % self.sysconfig.epiper_path())
            fh.write('user=root\n')
            fh.write('autostart=true\n')
            fh.write('autorestart=true\n')
            fh.write('stderr_logfile=/var/log/vpnauth-server.err.log\n')
            fh.write('stdout_logfile=/var/log/vpnauth-server.out.log\n')

        self.supervisor.ctl_refresh()

    def switch(self, start=None, stop=None, restart=None):
        """
        Starts/stops/restarts the service
        :param start:
        :param stop:
        :param restart:
        :return:
        """
        if restart or stop:
            self.supervisor.ctl_stop(self.SUPERVISOR_CMD)
        if restart or start:
            return self.supervisor.ctl_start(self.SUPERVISOR_CMD)


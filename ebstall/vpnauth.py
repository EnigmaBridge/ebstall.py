#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import errors
import collections
import re
import util
import json
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
    VPN_CONFIG_FILE = '/etc/openvpn/vpnauth.json'
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

        # Create VPN-dir based configuration for vpnauth notifier.
        # It is started under VPN server user so it has to be able to read the configuration with the API key.
        if os.path.exists(self.VPN_CONFIG_FILE):
            os.remove(self.VPN_CONFIG_FILE)
        with util.safe_open(self.VPN_CONFIG_FILE, mode='w', chmod=0o600) as fh:
            js = {'config': {'vpnauth_enc_password': self.config.vpnauth_enc_password}}
            json.dump(js, fh, indent=2)

        self.sysconfig.exec_shell('chown %s %s' % (self.ovpn.get_user(), self.VPN_CONFIG_FILE))

    def configure_vpn_server(self):
        """
        Configures VPN server to use VPNAuth event scripts
        :return:
        """
        epiper = self.sysconfig.epiper_path()
        connect = '%s vpnauth-notif --vpncfg --event connected' % epiper
        disconnect = '%s vpnauth-notif --vpncfg --event disconnected' % epiper
        up = '%s vpnauth-notif --vpncfg --event up' % epiper
        down = '%s vpnauth-notif --vpncfg --event down' % epiper
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


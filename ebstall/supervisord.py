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


class Supervisord(object):
    """
    Supervisord - keeping services running
    """
    CONFIG_FILE = '/etc/supervisord.conf'
    CONFIG_FILE_DIR = '/etc/supervisord.d/'

    def __init__(self, sysconfig=None, audit=None, write_dots=False, client_config_path=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dost = write_dots
        self.audit = audit

    #
    # Installation
    #

    def _install_package(self):
        """
        Installs supervisord from the package.
        :return: status code of the installer.
        """
        cmd_exec = 'sudo yum install -y supervisor'
        if self.sysconfig.get_packager() == osutil.PKG_APT:
            cmd_exec = 'sudo apt-get install -y supervisor'

        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dost)

    def _get_init_script(self):
        """
        Returns a static asset - init script
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('consts', 'supervisor-init.sh'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def _get_systemd_script(self):
        """
        Returns a static asset - systemd start script
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('consts', 'supervisor-systemd.sh'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def _install_systemd(self):
        """
        Installs start script systemd (centos/rhell 7+)
        :return:
        """
        # Write simple init script
        initd_path = '/etc/systemd/system/supervisor.service'
        if os.path.exists(initd_path):
            os.remove(initd_path)
            self.audit.audit_delete(initd_path)

        with util.safe_open(initd_path, mode='w', chmod=0o664) as handle:
            data = self._get_systemd_script()
            handle.write(data)
            handle.write('\n')
        self.audit.audit_file_write(initd_path)

        ret = self.sysconfig.exec_shell('sudo systemctl daemon-reload')
        if ret != 0:
            raise errors.SetupError('Error: Could not reload systemctl, code: %s\n' % ret)

        return 0

    def _install_initd(self):
        """
        Installs stat script in initd system
        :return:
        """
        # Write simple init script
        initd_path = '/etc/init.d/supervisor'
        if os.path.exists(initd_path):
            os.remove(initd_path)
            self.audit.audit_delete(initd_path)

        with util.safe_open(initd_path, mode='w', chmod=0o755) as handle:
            data = self._get_init_script()
            handle.write(data)
            handle.write('\n')
        self.audit.audit_file_write(initd_path)

        ret = self.sysconfig.exec_shell('sudo chkconfig --add supervisor')
        if ret != 0:
            raise errors.SetupError('Error: Could not reload systemctl, code: %s\n' % ret)

        return 0

    def _install_startup(self):
        """
        Installs init script
        :return:
        """
        start_system = self.sysconfig.get_start_system()
        if start_system == osutil.START_SYSTEMD:
            return self._install_systemd()

        # Fallback to default initd start system
        return self._install_initd()

    def _configure(self):
        """
        Configures supervisord after manual installation
        :return:
        """
        cmd_prep = '%s echo_supervisord_conf > %s' % (self.sysconfig.epiper_path(), self.CONFIG_FILE)
        ret = self.sysconfig.exec_shell(cmd_prep)
        if ret != 0:
            raise errors.SetupError('Could not initialize supervisord config file')

        if not os.path.exists(self.CONFIG_FILE_DIR):
            util.make_or_verify_dir(self.CONFIG_FILE_DIR)

        with open(self.CONFIG_FILE, 'a') as fh:
            fh.write('\n')
            fh.write('[include]\n')
            fh.write('files = /etc/supervisord.d/*.conf\n\n')

    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        install_package = self._install_package()
        if install_package == 0:
            self._configure()
            return 0

        # Packager could not install it
        cmd_exec = 'sudo pip install supervisor'
        ret = self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dost)
        if ret != 0:
            raise errors.SetupError('Could not install supervisord from the pip')

        self._configure()
        self._install_startup()
        return 0

    def get_svc_map(self):
        """
        Returns service naming for different start systems
        :return:
        """
        return {
            osutil.START_SYSTEMD: 'supervisor.service',
            osutil.START_INITD: 'supervisor'
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

    #
    # API
    #

    def ctl_refresh(self):
        """
        supervisorctl reread
        supervisorctl update
        :return:
        """
        ret = self.sysconfig.exec_shell('sudo %s supervisorctl reread' % self.sysconfig.epiper_path())
        if ret != 0:
            raise errors.SetupError('Could not exec supervisorctl reread')

        ret = self.sysconfig.exec_shell('sudo %s supervisorctl update' % self.sysconfig.epiper_path())
        if ret != 0:
            raise errors.SetupError('Could not exec supervisorctl update')

    def ctl_add(self, cmd):
        """
        :return:
        """
        ret = self.sysconfig.exec_shell('sudo %s supervisorctl add %s'
                                        % (self.sysconfig.epiper_path(), util.escape_shell(cmd)))
        if ret != 0:
            raise errors.SetupError('Could not exec supervisorctl add')

    def ctl_start(self, cmd):
        """
        :return:
        """
        ret = self.sysconfig.exec_shell('sudo %s supervisorctl start %s'
                                        % (self.sysconfig.epiper_path(), util.escape_shell(cmd)))
        if ret != 0:
            raise errors.SetupError('Could not exec supervisorctl start')

    def ctl_stop(self, cmd):
        """
        :return:
        """
        ret = self.sysconfig.exec_shell('sudo %s supervisorctl stop %s'
                                        % (self.sysconfig.epiper_path(), util.escape_shell(cmd)))
        if ret != 0:
            raise errors.SetupError('Could not exec supervisorctl stop')


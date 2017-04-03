#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import ebstall.errors as errors
import collections
import re
import ebstall.util as util
import subprocess
import types
import ebstall.osutil as osutil
import shutil
import pkg_resources


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class IniParser(object):
    """
    Very simple INI file parser
    """
    def __init__(self, file_name=None, file_data=None):
        self.data = None
        self.file_name = file_name
        self.file_data = file_data
        self.dirty = False

    def load(self):
        if self.file_data is not None:
            if isinstance(self.file_data, types.ListType):
                self.data = self.file_data
            else:
                self.data = self.file_data.split('\n')
            return

        if self.file_name is not None:
            with open(self.file_name, 'r') as fh:
                self.data = [x.strip() for x in fh]
            return

        raise ValueError('No data to process')

    def set_value(self, key, value, remove=False):
        """
        Sets the config value
        :param key: 
        :param value: 
        :param remove: 
        :return: 
        """
        if self.data is None:
            self.load()

        new_cfg = '%s = %s' % (key, value)
        last_idx = len(self.data) - 1

        for idx, line in enumerate(self.data):
            if re.match(r'^;\s*%s' % re.escape(key), line):
                last_idx = idx

            elif re.match(r'^\s*%s' % re.escape(key), line):
                self.data[idx] = new_cfg
                self.dirty = True
                return

        self.data.insert(last_idx+1, new_cfg)
        self.dirty = True

    def get_value(self, key):
        """
        Returns config value for the given key
        :param key: 
        :return: 
        """
        if self.data is None:
            self.load()

        for idx, line in enumerate(self.data):
            if re.match(r'^\s*%s' % re.escape(key), line):
                parts = line.split('=', 1)
                if len(parts) == 1:
                    return None

                return parts[1].strip()
        return None

    def flush(self):
        """
        If dirty & using file, flushes changes to the file
        :return: 
        """
        if not self.dirty:
            return

        if self.file_name is None:
            return None

        with open(self.file_name, 'w') as fh:
            fh.write('\n'.join(self.data))
        self.dirty = False


class Php(object):
    """
    PHP installer & configurator
    """
    CONFIG_FILE = '/etc/php.ini'
    CONFIG_FPM_WWW = '/etc/php-fpm.d/www.conf'

    def __init__(self, sysconfig=None, audit=None, write_dots=False, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dost = write_dots
        self.audit = audit
        self.user = 'nginx'

    #
    # Installation
    #

    def _install_package(self):
        """
        Installs from the package.
        
        :return: status code of the installer.
        """
        if self.sysconfig.get_packager() == osutil.PKG_APT:
            cmd_exec = 'sudo apt-get install -y php-fpm php-mysql php-mbstring php-gd'
            return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dost)

        if self.sysconfig.get_packager() != osutil.PKG_YUM:
            raise errors.SetupError('Unsupported packager, cannot install PHP')

        # Check out versions available
        packages = ['php*-fpm', 'php*-mysqlnd', 'php*-mbstring', 'php*-gd', 'php*-xml']

        cmd_version = 'sudo repoquery ' + (' '.join(packages))
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd_version, shell=True)
        if ret != 0:
            raise errors.SetupError('Could not determine available PHP versions')

        versions = util.get_repoquery_available_versions(out)

        # Prefer versions 5.6
        versions_to_install = util.repoquery_find_version(versions, exact_version='5.6')
        if len(versions_to_install) < len(packages):
            versions_to_install = util.repoquery_find_version(versions, min_version='5.6', max_version='5.99')
            versions_to_install = util.repoquery_pick_version(versions_to_install, pick_min=True)

        if len(versions_to_install) < len(packages):
            raise errors.SetupError('Could not install all packages')

        packages_to_install = [x[0] for x in versions_to_install]
        cmd_exec = 'sudo yum install -y ' + (' '.join(packages_to_install))
        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dost)

    def configure(self):
        """
        Configures PHP installation for Nginx
        :return:
        """

        # Change CGI path info
        main_ini = IniParser(file_name=self.CONFIG_FILE)
        main_ini.set_value('cgi.fix_pathinfo', '1')
        main_ini.flush()

        # Change user for nginx
        www_ini = IniParser(file_name=self.CONFIG_FPM_WWW)
        www_ini.set_value('user', self.user)
        www_ini.set_value('group', self.user)
        www_ini.flush()

        # Get directory for sessions, create & setup if non-existing
        spath = www_ini.get_value('session.save_path')
        if spath is None:
            spath = www_ini.get_value('php_value[session.save_path]')

        base_path = '/var/lib/php'
        util.makedirs(base_path, mode=0o755)
        util.chown(base_path, self.user)

        if spath is not None:
            util.makedirs(spath, mode=0o755)
            util.chown(spath, self.user)

    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        install_package = self._install_package()
        if install_package == 0:
            return 0

        raise errors.SetupError('Cannot install PHP')

    def get_svc_map(self):
        """
        Returns service naming for different start systems
        :return:
        """
        return {
            osutil.START_SYSTEMD: 'php-fpm.service',
            osutil.START_INITD: 'php-fpm'
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


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
import nginxparser_eb


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class Nginx(object):
    """
    Nginx server
    """
    SETTINGS_FILE = '/etc/nginx/nginx.conf'
    DEFAULT_PRIVATE_SPACE_GIT = 'https://github.com/EnigmaBridge/privatespace.git'

    def __init__(self, sysconfig=None, write_dots=False, audit=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dots = write_dots
        self.audit = audit
        self.hostname = 'private-space'
        self.html_root = '/usr/share/nginx/html'

    #
    # server.conf reading & modification
    #

    def get_config_file_path(self):
        """
        Returns config file path
        :return: server config file path
        """
        return self.SETTINGS_FILE

    def load_html_root(self):
        """
        Loads path to the default root
        :return:
        """
        cfg_path = self.get_config_file_path()
        if not os.path.exists(cfg_path):
            logger.debug('Nginx config file %s not found' % cfg_path)
            return None

        logger.debug('Parsing nginx config: %s' % cfg_path)
        with open(cfg_path, 'r') as fh:
            cfg = nginxparser_eb.load(fh)
            root = self._find_root(cfg)
            if root is not None:
                self.html_root = root

        return self.html_root

    def _find_root(self, cfg, path=None):
        """
        Finding root directive
        :param cfg:
        :return:
        """
        if not isinstance(cfg, types.ListType):
            raise ValueError('Configuration is not a list')
        if path is None:
            path = []

        if len(cfg) <= 1:
            return None

        if len(cfg) == 2:
            if isinstance(cfg[0], types.ListType):  # 2, first is list -> section opening
                path = list(path) + [cfg[0]]
                return self._find_root(cfg[1], path)

            elif cfg[0] == 'root':  # not a list -> string
                logger.debug('Nginx root found: %s, path: %s' % (cfg[1], path))
                return cfg[1]

        for sub in cfg:
            if isinstance(sub, types.ListType):
                ret = self._find_root(sub, list(path))
                if ret is not None:
                    return ret

        return None

    def get_git_repo(self):
        """
        Returns a git repo with private space intro page
        :return:
        """
        return self.DEFAULT_PRIVATE_SPACE_GIT

    def templatize_file(self, file_path, ignore_not_found=False):
        """
        Fils in the template placeholders in the file.
        :param file_path:
        :param ignore_not_found:
        :return:
        """
        if not os.path.exists(file_path):
            if ignore_not_found:
                return
            raise errors.SetupError('Could not find file to templatize: %s' % file_path)

        data = None
        with open(file_path, 'r') as fh:
            data = fh.read()
            data = data.replace('{{ private_space_intro_link }}', 'https://%s:8442' % self.hostname)
            data = data.replace('{{ private_space_name_full }}', self.hostname)
            data = data.replace('{{ private_space_name_short }}', util.get_leftmost_domain(self.hostname))

        with open(file_path, 'w') as fh:
            fh.write(data)

    #
    # Configuration
    #

    def configure_server(self):
        """
        Perform base server configuration.
        :return: True if file was changed
        """

        root = self.load_html_root()
        if root is None:
            raise errors.SetupError('Could not determine default root of the Nginx server')

        if os.path.exists(root):
            util.dir_backup(root, backup_dir='/tmp')
            shutil.rmtree(root)

        util.make_or_verify_dir(root)

        # Clone git repo here
        cmd = 'git clone "%s" "%s"' % (self.get_git_repo(), root)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd)
        if ret != 0:
            raise errors.SetupError('Git clone of the private space repo failed')

        # Update index.html
        self.templatize_file(os.path.join(root, 'index.html'))
        self.templatize_file(os.path.join(root, '404.html'), ignore_not_found=True)
        self.templatize_file(os.path.join(root, '50x.html'), ignore_not_found=True)

        return False

    #
    # Installation
    #
    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        cmd_exec = 'sudo yum install -y nginx'
        if self.sysconfig.get_packager() == osutil.PKG_APT:
            cmd_exec = 'sudo apt-get install -y nginx'

        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dots)

    def get_svc_map(self):
        """
        Returns service naming for different start systems
        :return:
        """
        return {
            osutil.START_SYSTEMD: 'nginx.service',
            osutil.START_INITD: 'nginx'
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





#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import ebstall.errors as errors
import collections
import re
import ebstall.util as util
import json
import subprocess
import types
import ebstall.osutil as osutil
import shutil
import random
import pkg_resources


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class PrivSpaceWeb(object):
    """
    VPN Auth server
    """
    CONFIG_FILE = '.env'
    DB_USER = 'privatespace'
    DB_NAME = 'privatespace'
    WEBROOT = '/var/www/privatespace'
    DEFAULT_PRIVATE_SPACE_GIT = 'https://github.com/EnigmaBridge/privatespace2.git'

    def __init__(self, sysconfig=None, audit=None, write_dots=False, mysql=None, config=None, nginx=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dost = write_dots
        self.audit = audit
        self.mysql = mysql
        self.config = config
        self.nginx = nginx
        self.webroot = self.WEBROOT
        self.stats_file_path = None

        self.user = 'nginx'
        self.admin_email = None
        self.hostname = None
        self.vpn_net_addr = None
        self.vpn_net_size = None
        self.vpn_net_server = None

    def get_git_repo(self):
        """
        Returns a git repo with private space intro page
        :return:
        """
        return self.DEFAULT_PRIVATE_SPACE_GIT

    def get_public_dir(self):
        """
        Returns the public directory the nginx should point its root directive
        :return: 
        """
        return os.path.join(self.webroot, 'public')

    def _get_env_template(self):
        """
        ENV template for the Laravel web
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('..', 'consts', 'pspace.env'))
        return pkg_resources.resource_string(resource_package, resource_path)

    #
    # Installation
    #

    def _cfg_str(self, x):
        """
        Returns empty string if is none
        :param x: 
        :return: 
        """
        if x is None:
            return ''
        return '%s' % x

    def _configure_env(self, env_path):
        """
        Creates env configuration file for Laravel
        :param env_path: 
        :return: 
        """
        tpl_file = self._get_env_template()
        tpl_file = tpl_file.replace('{{ APP_URL }}', 'https://%s:8442' % self.hostname)
        tpl_file = tpl_file.replace('{{ APP_PRIVATE_SPACE_NAME }}', self._cfg_str(self.hostname))
        tpl_file = tpl_file.replace('{{ APP_ADMIN }}', self._cfg_str(self.admin_email))
        tpl_file = tpl_file.replace('{{ APP_STATS }}', self._cfg_str(self.stats_file_path))
        tpl_file = tpl_file.replace('{{ APP_VPN_NET_ADDR }}', self._cfg_str(self.vpn_net_addr))
        tpl_file = tpl_file.replace('{{ APP_VPN_NET_SIZE }}', self._cfg_str(self.vpn_net_size))

        tpl_file = tpl_file.replace('{{ DB_DATABASE }}', self._cfg_str(self.config.pspace_db))
        tpl_file = tpl_file.replace('{{ DB_USERNAME }}', self._cfg_str(self.config.pspace_db_user))
        tpl_file = tpl_file.replace('{{ DB_PASSWORD }}', self._cfg_str(self.config.pspace_db_password))

        # Remove all other templates not filled in
        tpl_file = re.sub(r'\{\{\s*[a-zA-Z0-9_\-]+\s*\}\}', '', tpl_file)

        with open(env_path, mode='w') as fh:
            fh.write(tpl_file)

        cmd = 'sudo -E -H chown %s "%s"' % (self.user, env_path)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=self.webroot)
        if ret != 0:
            raise errors.SetupError('Could not change .env owner')

    def configure(self):
        """
        Configures supervisord after manual installation
        :return:
        """
        self.config.pspace_db = self.DB_NAME
        self.config.pspace_db_user = self.DB_USER
        self.config.pspace_db_password = util.random_password(16)
        self.audit.add_secrets(self.config.pspace_db_password)

        # Create mysql database and user
        self.mysql.drop_database(self.config.pspace_db)
        self.mysql.create_database(self.config.pspace_db)
        self.mysql.create_user(self.DB_USER, self.config.pspace_db_password, self.config.pspace_db)

        # Create .env config file.
        env_path = os.path.join(self.webroot, '.env')
        if os.path.exists(env_path):
            util.file_backup(env_path)
            os.remove(env_path)

        # Env path config
        self._configure_env(env_path)

        # Composer install
        cmd = 'sudo -E -H -u %s composer install' % self.user
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=self.webroot)
        if ret != 0:
            raise errors.SetupError('Could not install dependencies')

        # Artisan - generate new fresh app key
        cmd = 'sudo -E -H -u %s php artisan key:generate' % self.user
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=self.webroot)
        if ret != 0:
            raise errors.SetupError('Could not create a new app key for privatespace')

        # Artisan migrate - create DB structure
        cmd = 'sudo -E -H -u %s php artisan migrate --force' % self.user
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=self.webroot)
        if ret != 0:
            raise errors.SetupError('Could not initialize DB for privatespace')

    def _install_composer(self):
        """
        Installs PHP composer
        :return: 
        """

        tmpdir = os.path.join('/tmp', 'tmp-composer.%08d' % random.randint(0, 2**31))
        if os.path.exists(tmpdir):
            shutil.rmtree(tmpdir)

        util.make_or_verify_dir(tmpdir)
        composer_installer = os.path.join(tmpdir, 'composer-setup.php')

        cmd = 'curl -s "%s" > "%s"' % ('https://getcomposer.org/installer', composer_installer)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=tmpdir)
        if ret != 0:
            raise errors.SetupError('Could not download composer')

        cmd = 'sudo php "%s" --install-dir=/bin --filename=composer' % composer_installer
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=tmpdir)
        if ret != 0:
            raise errors.SetupError('Could not install composer')

        shutil.rmtree(tmpdir)

    def _install_deps(self):
        """
        Installs dependencies for the private space: composer.
        :return: 
        """
        self._install_composer()

    def install(self):
        """
        Installs itself
        :return: installer return code
        """

        # Remove webroot if exists
        if os.path.exists(self.webroot):
            util.dir_backup(self.webroot, backup_dir='/tmp')
        if os.path.exists(self.webroot):
            shutil.rmtree(self.webroot)

        # Git clone
        cmd = 'git clone "%s" "%s"' % (self.get_git_repo(), self.webroot)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd)
        if ret != 0:
            raise errors.SetupError('Git clone of the private space repo failed')

        # Dependencies
        self._install_deps()

        # Privileges
        storage_dir = os.path.join(self.webroot, 'storage', 'bootstrap', 'cache')
        cache_sub_dir = os.path.join(storage_dir, 'bootstrap', 'cache')
        if not os.path.exists(cache_sub_dir):
            os.makedirs(cache_sub_dir, mode=0o775)

        cmd = 'sudo chown %s -R "%s"' % (self.user, self.webroot)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd)
        if ret != 0:
            raise errors.SetupError('Owner change failed for private space web')

        cmd = 'sudo chmod 775 -R "%s"' % storage_dir
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd)
        if ret != 0:
            raise errors.SetupError('Permission change failed for private space web')

        return 0

    def enable(self):
        """
        Enables service after OS start
        :return:
        """
        return 0

    def switch(self, start=None, stop=None, restart=None):
        """
        Starts/stops/restarts the service
        :param start:
        :param stop:
        :param restart:
        :return:
        """
        return 0





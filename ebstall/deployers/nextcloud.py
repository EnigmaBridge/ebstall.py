#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import ebstall.errors as errors
import collections
import re
import requests
import ebstall.util as util
import types
import ebstall.osutil as osutil
import shutil
import pkg_resources

from ebstall.consts import PROVISIONING_SERVERS
from ebstall.deployers import letsencrypt

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class NextCloud(object):
    """
    Nextcloud module
    """
    WEBROOT = '/var/www/nextcloud'

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
        self.hostname = None

    def get_subdomains(self):
        """
        Returns domains to register
        :return: 
        """
        return ['cloud']

    def get_domains(self):
        """
        Full domains based on the hostname
        :return: 
        """
        return ['%s.%s' % (x, self.hostname) for x in self.get_subdomains()]

    #
    # Configuration
    #

    def _get_tls_paths(self):
        """
        Returns chain & key path for TLS or None, None
        :return: keychain path, privkey path
        """
        cert_dir = os.path.join(letsencrypt.LE_CERT_PATH, self.hostname)
        cert_path = os.path.join(cert_dir, letsencrypt.LE_CA)
        key_path = os.path.join(cert_dir, letsencrypt.LE_PRIVATE_KEY)
        return cert_path, key_path

    def _get_php_trusted_domains_template(self):
        """
        Returns php file for changing owncloud settings
        :return: 
        """
        resource_package = __name__
        resource_path = '/'.join(('..', 'consts', 'nextcloud-trusteddomains.php'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def _get_nginx_template(self):
        """
        Returns static nginx config template
        :return: 
        """
        resource_package = __name__
        resource_path = '/'.join(('..', 'consts', 'nginx-nextcloud.conf'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def _cfg_str(self, x):
        """
        Returns empty string if is none
        :param x: 
        :return: 
        """
        if x is None:
            return ''
        return '%s' % x

    def _get_nginx_cfg(self):
        """
        Creates nginx configuration file
        :param env_path: 
        :return: 
        """
        cert_path, key_path = self._get_tls_paths()
        tpl_file = self._get_nginx_template()
        tpl_file = tpl_file.replace('{{ DOMAINS }}', ','.join(self.get_domains()))
        tpl_file = tpl_file.replace('{{ TLS_CERT }}', self._cfg_str(cert_path))
        tpl_file = tpl_file.replace('{{ TLS_KEY }}', self._cfg_str(key_path))
        tpl_file = tpl_file.replace('{{ WEBROOT }}', self._cfg_str(self.webroot))

        # Remove all other templates not filled in
        tpl_file = re.sub(r'\{\{\s*[a-zA-Z0-9_\-]+\s*\}\}', '', tpl_file)
        return tpl_file

    def configure(self):
        """
        Configures Nginx
        :return: 
        """
        cfg_dir = self.nginx.http_include
        path = os.path.join(cfg_dir, 'nextcloud.conf')
        util.safely_remove(path)

        with util.safe_open(path, mode='w', chmod=0o644) as fh:
            fh.write(self._get_nginx_cfg()+'\n')

    #
    # Installation
    #

    def _download_file(self, url, filename):
        """
        Downloads binary file, saves to the file
        :param url:
        :param filename:
        :return:
        """
        r = requests.get(url, stream=True, timeout=15)
        with open(filename, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

        return filename

    def _fix_privileges(self):
        """
        Fixes privileges to the files
        :return: 
        """
        # Privileges
        storage_dir = os.path.join(self.webroot, 'storage', 'bootstrap', 'cache')
        cache_sub_dir = os.path.join(storage_dir, 'bootstrap', 'cache')
        if not os.path.exists(cache_sub_dir):
            os.makedirs(cache_sub_dir, mode=0o775)

        cmd = 'sudo chown %s -R "%s"' % (self.user, self.webroot)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd)
        if ret != 0:
            raise errors.SetupError('Owner change failed for private space web')

    def _deploy_downloaded(self, archive_path, basedir):
        """
        Analyzes downloaded file, deploys to the webroot
        :param archive_path:
        :param basedir:
        :return:
        """
        cmd = 'sudo unzip %s' % util.escape_shell(archive_path)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, write_dots=True, cwd=basedir)
        if ret != 0:
            raise errors.SetupError('Could not extract update archive')

        folders = [f for f in os.listdir(basedir) if not os.path.isfile(os.path.join(basedir, f))
                   and f != '.' and f != '..']

        if len(folders) != 1:
            raise errors.SetupError('Invalid folder structure after update extraction')

        archive_dir = os.path.join(basedir, folders[0])
        if not os.path.exists(archive_dir):
            raise errors.SetupError('Directory with nextcloud not found in the update archive: %s' % archive_dir)
        if not os.path.exists(os.path.join(archive_dir, 'robots.txt')):
            raise errors.SetupError('Invalid update archive, robots.txt not found in %s' % archive_dir)

        archive_slash = archive_dir if archive_dir.endswith('/') else archive_dir + '/'
        dest_slash = self.webroot
        dest_slash = dest_slash if dest_slash.endswith('/') else dest_slash + '/'

        cmd = 'sudo rsync -av --delete "%s" "%s"' % (archive_slash, dest_slash)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, write_dots=True, cwd=basedir)
        if ret != 0:
            raise errors.SetupError('nextcloud sync failed')

        self._fix_privileges()

    def _install(self, attempts=3):
        """
        Downloads a new revision of the EJBCA from the provisioning server, if possible
        :return:
        """
        base_file = 'nextcloud-11.0.3.zip'
        try:
            logger.debug('Going to download specs from the provisioning servers')
            for provserver in PROVISIONING_SERVERS:
                url = 'https://%s/nextcloud/%s' % (provserver, base_file)
                tmpdir = util.safe_new_dir('/tmp/nextcloud-install')

                for attempt in range(attempts):
                    try:
                        self.audit.audit_evt('prov-nextcloud', url=url)

                        # Download archive.
                        archive_path = os.path.join(tmpdir, base_file)
                        self._download_file(url, archive_path)

                        # Update
                        self._deploy_downloaded(archive_path, tmpdir)
                        return 0

                    except errors.SetupError as e:
                        logger.debug('SetupException in fetching NextCloud from the provisioning server: %s' % e)
                        self.audit.audit_exception(e, process='prov-nextcloud')

                    except Exception as e:
                        logger.debug('Exception in fetching NextCloud from the provisioning server: %s' % e)
                        self.audit.audit_exception(e, process='prov-nextcloud')

                    finally:
                        if os.path.exists(tmpdir):
                            shutil.rmtree(tmpdir)

                return 0

        except Exception as e:
            logger.debug('Exception when fetching NextCloud')
            self.audit.audit_exception(e)
        return -1

    def _occ_install(self):
        """
        Owncloud installer script
        :return: 
        """
        admin_pass = util.random_password(14)
        self.config.nextcloud_admin_pass = admin_pass
        self.audit.add_secrets(admin_pass)

        cmd = 'sudo -u %s php occ maintenance:install ' \
              ' --database mysql --database-name owncloud  --database-user root --database-pass %s  ' \
              ' --admin-user admin --admin-pass %s' % (self.user, self.mysql.get_root_password(), admin_pass)

        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=self.webroot)
        if ret != 0:
            raise errors.SetupError('Owner change failed for private space web')

    def _trusted_domains(self):
        """
        Trusted domains configuration - modifies config.php and adds current domain to the trusted_domains config key
        :return: 
        """
        cfg_path = os.path.join(self.webroot, 'config', 'config.php')
        if not os.path.exists(cfg_path):
            logger.warning('NextCloud config file not found: %s' % cfg_path)
            raise errors.SetupError('NextCloud config file not found')

        tpl_file = self._get_php_trusted_domains_template()
        tpl_file = tpl_file.replace('{{ CONFIG_FILE }}', cfg_path)
        tpl_file = re.sub(r'\{\{\s*[a-zA-Z0-9_\-]+\s*\}\}', '', tpl_file)

        php_file = os.path.join(self.webroot, 'ebstall-config.php')
        util.safely_remove(php_file)
        with util.safe_open(php_file, 'w', 0o755) as fw:
            fw.write(tpl_file)

        domains_list = ' '.join(self.get_domains() + [self.hostname])
        cmd = 'sudo -u %s php %s %s ' \
              % (self.user, php_file, domains_list)

        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=self.webroot)
        if ret != 0:
            raise errors.SetupError('Owner change failed for private space web')

        new_cfg = '<?php\n $CONFIG = %s; \n' % out
        with open(cfg_path, 'w') as fw:
            fw.write(new_cfg)

    def _install_ojsxc(self):
        """
        Installs chat plugin app
        :return: 
        """


    def _install_vpnauth(self):
        """
        Installs vpnauth app
        :return: 
        """



    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        ret = self._install(attempts=3)
        if ret != 0:
            raise errors.SetupError('Could not install NextCloud')

        self._occ_install()
        self._trusted_domains()
        self._install_ojsxc()
        self._install_vpnauth()
        self._fix_privileges()
        return 0






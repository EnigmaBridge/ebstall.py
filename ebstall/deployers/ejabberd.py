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
import ruamel.yaml
import time
import pkg_resources

from ebstall.consts import PROVISIONING_SERVERS
from ebstall.deployers import letsencrypt

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class Ejabberd(object):
    """
    Nextcloud module
    """

    def __init__(self, sysconfig=None, audit=None, write_dots=False, config=None,  *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dots = write_dots
        self.audit = audit
        self.config = config
        self.hostname = None

        self.root_dir = None
        self.config_dir = None
        self.bin_dir = None
        self.ejabberctl = None
        self.bin_initd_script = None
        self.bin_svc_script = None

        self.file_rpm = 'ejabberd-17.04-0.x86_64.rpm'
        self.file_deb = 'ejabberd_17.04-0_amd64.deb'

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

    def _find_dirs(self):
        """
        Finds the ejabberd root dir
        :return: 
        """
        folders = [f for f in os.listdir('/opt') if not os.path.isfile(os.path.join('/opt', f))
                   and f != '.' and f != '..' and f.startswith('ejabberd')]

        if len(folders) > 1:
            logger.debug('Too many ejabberd folders, picking the last one')
        if len(folders) > 0:
            self.root_dir = folders[-1]
            self.config_dir = os.path.join(self.root_dir, 'conf')
            self.bin_dir = os.path.join(self.root_dir, 'bin')
            self.ejabberctl = os.path.join(self.bin_dir, 'ejabberdctl')
            self.bin_initd_script = os.path.join(self.bin_dir, 'ejabberd.init')
            self.bin_svc_script = os.path.join(self.bin_dir, 'ejabberd.service')
            return

        raise errors.SetupError('Could not find Ejabberd folders')

    def _config(self):
        """
        Configures ejabberd server
        :return: 
        """
        config_file = os.path.join(self.config_dir, 'ejabberd.yml')
        config_data = open(config_file).read()
        config_yml = ruamel.yaml.round_trip_load(config_data)

        # virtual host setup
        config_yml['hosts'] = [self.hostname]

        # TODO: external authentication setup
        # '/opt/xmpp-cloud-auth/external_cloud.py -t ejabberd -u https://cloud.tunbridge1.umph.io/index.php/apps/ojsxc/ajax/externalApi.php -s i0GBR5ZD0BDexaXpo7Pta58

        with open(config_file, 'w') as fh:
            new_config = ruamel.yaml.round_trip_dump(config_yml)
            fh.write(new_config)

    def configure(self):
        """
        Configures ejabberd server
        :return: 
        """
        self._find_dirs()

        start_system = self.sysconfig.get_start_system()
        if start_system == osutil.START_INITD:
            self.sysconfig.install_initd_svc('ejabberd', script_path=self.bin_initd_script)
        elif start_system == osutil.START_SYSTEMD:
            self.sysconfig.install_systemd_svc('ejabberd', script_path=self.bin_svc_script)
        else:
            raise errors.EnvError('Unknown start system, could not setup ')

        self._config()

    def get_svc_map(self):
        """
        Returns service naming for different start systems
        :return:
        """
        return {
            osutil.START_SYSTEMD: 'ejabberd.service',
            osutil.START_INITD: 'ejabberd'
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
    # Installation
    #

    def _download_file(self, url, filename, attempts=1):
        """
        Downloads binary file, saves to the file
        :param url:
        :param filename:
        :return:
        """
        return util.download_file(url, filename, attempts)

    def _deploy_downloaded(self, archive_path, basedir):
        """
        Analyzes downloaded file, deploys to the webroot
        :param archive_path:
        :param basedir:
        :return:
        """
        cmd_exec = None
        pkg = self.sysconfig.get_packager()
        if pkg == osutil.PKG_YUM:
            cmd_exec = 'sudo yum localinstall -y %s' % util.escape_shell(archive_path)
        elif pkg == osutil.PKG_APT:
            cmd_exec = 'sudo dpkg -i %s' % util.escape_shell(archive_path)

        ret = self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dots)
        if ret != 0:
            raise errors.SetupError('Could not install ejabberd server')

    def _install(self, attempts=3):
        """
        Downloads ejabberd install package from the server, installs it.
        :return:
        """
        pkg = self.sysconfig.get_packager()
        if pkg == osutil.PKG_YUM:
            base_file = self.file_rpm
        elif pkg == osutil.PKG_APT:
            base_file = self.file_deb
        else:
            raise errors.EnvError('Unsupported package manager for ejabberd server')

        try:
            logger.debug('Going to download nextcloud from the provisioning servers')
            for provserver in PROVISIONING_SERVERS:
                url = 'https://%s/ejabberd/%s' % (provserver, base_file)
                tmpdir = util.safe_new_dir('/tmp/ejabberd-install')

                try:
                    self.audit.audit_evt('prov-ejabberd', url=url)

                    # Download archive.
                    archive_path = os.path.join(tmpdir, base_file)
                    self._download_file(url, archive_path, attempts=attempts)

                    # Update
                    self._deploy_downloaded(archive_path, tmpdir)
                    return 0

                except errors.SetupError as e:
                    logger.debug('SetupException in fetching Ejabberd from the provisioning server: %s' % e)
                    self.audit.audit_exception(e, process='prov-ejabberd')

                except Exception as e:
                    logger.debug('Exception in fetching Ejabberd from the provisioning server: %s' % e)
                    self.audit.audit_exception(e, process='prov-ejabberd')

                finally:
                    if os.path.exists(tmpdir):
                        shutil.rmtree(tmpdir)

                return 0

        except Exception as e:
            logger.debug('Exception when fetching Ejabberd')
            self.audit.audit_exception(e)
            raise errors.SetupError('Could not install Ejabberd', cause=e)

    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        ret = self._install(attempts=3)
        if ret != 0:
            raise errors.SetupError('Could not install Ejabberd')
        return 0






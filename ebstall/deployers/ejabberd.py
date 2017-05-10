#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import ebstall.errors as errors
import os
import ebstall.util as util
import types
import ebstall.osutil as osutil
import shutil
import time

import ruamel.yaml
from ruamel.yaml.scalarstring import DoubleQuotedScalarString, SingleQuotedScalarString

from ebstall.consts import PROVISIONING_SERVERS
from ebstall.deployers import letsencrypt

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class Ejabberd(object):
    """
    Nextcloud module
    """

    def __init__(self, sysconfig=None, audit=None, write_dots=False, config=None, certificates=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dots = write_dots
        self.audit = audit
        self.config = config
        self.certificates = certificates
        self.hostname = None
        self.extauth_endpoint = None
        self.extauth_token = None

        # Detected paths & env
        self._root_dir = None
        self._config_dir = None
        self._bin_dir = None
        self._ejabberctl = None
        self._bin_initd_script = None
        self._bin_svc_script = None
        self._server_cert_path = None
        self._user = None
        self._group = None

        # Paths & components urls
        self._file_rpm = 'ejabberd-17.04-0.x86_64.rpm'
        self._file_deb = 'ejabberd_17.04-0_amd64.deb'
        self._file_extauth = 'https://github.com/EnigmaBridge/xmpp-cloud-auth/archive/v0.1.tar.gz'

        # Static settings
        self._extauth_path = '/opt/xmpp-cloud-auth'
        self._extauth_log_dir = '/var/log/ejabberd'
        self._shared_group = 'Everybody'

    #
    # Configuration
    #

    def _get_tls_paths(self):
        """
        Returns chain & key path for TLS or None, None
        :return: keychain path, privkey path
        """
        hostname = self.hostname
        if hostname is None and self.config is not None:
            hostname = self.config.hostname

        cert_dir = os.path.join(letsencrypt.LE_CERT_PATH, self.hostname)
        cert_path = os.path.join(cert_dir, letsencrypt.LE_CA)
        key_path = os.path.join(cert_dir, letsencrypt.LE_PRIVATE_KEY)
        return cert_path, key_path

    def _find_dirs(self):
        """
        Finds the ejabberd root dir
        :return: 
        """
        base = '/opt'
        folders = [os.path.join(base, f) for f in os.listdir(base)
                   if not os.path.isfile(os.path.join(base, f)) and
                   f != '.' and f != '..' and f.startswith('ejabberd')]

        if len(folders) > 1:
            logger.debug('Too many ejabberd folders, picking the last one')
        if len(folders) > 0:
            self._root_dir = folders[-1]
            self._config_dir = os.path.join(self._root_dir, 'conf')
            self._bin_dir = os.path.join(self._root_dir, 'bin')
            self._ejabberctl = os.path.join(self._bin_dir, 'ejabberdctl')
            self._bin_initd_script = os.path.join(self._bin_dir, 'ejabberd.init')
            self._bin_svc_script = os.path.join(self._bin_dir, 'ejabberd.service')
            self._server_cert_path = os.path.join(self._config_dir, 'server.pem')

            cfg_stat = os.stat(self._config_dir)
            self._user = cfg_stat.st_uid
            self._group = cfg_stat.st_gid
            return

        raise errors.SetupError('Could not find Ejabberd folders')

    def _find_dirs_if_needed(self):
        """
        If dirs not found yet - do it
        :return: 
        """
        if self._root_dir is None:
            self._find_dirs()

    def _config(self):
        """
        Configures ejabberd server
        :return: 
        """
        self._find_dirs_if_needed()
        config_file = os.path.join(self._config_dir, 'ejabberd.yml')
        config_file_backup = os.path.join(self._config_dir, 'ejabberd.yml.backup')

        # Backup the config file. If config is present, use that one
        if os.path.exists(config_file_backup):
            shutil.copy(config_file_backup, config_file)
        else:
            shutil.copy(config_file, config_file_backup)

        config_data = open(config_file).read()
        config_yml = ruamel.yaml.round_trip_load(config_data, preserve_quotes=True)

        # virtual host setup
        config_yml['hosts'] = [DoubleQuotedScalarString(self.hostname)]

        # external authentication setup
        ext_auth_path = os.path.join(self._extauth_path, 'external_cloud.py')
        config_yml['auth_method'] = SingleQuotedScalarString('external')
        config_yml['extauth_cache'] = 0
        config_yml['extauth_program'] = DoubleQuotedScalarString(
            '%s -t ejabberd -s %s -u %s' % (ext_auth_path, self.extauth_token, self.extauth_endpoint))

        # add admin user - from NextCloud
        if self.hostname is None and self.config is not None:
            self.hostname = self.config.hostname
        util.setpath(config_yml, ['acl', 'admin', 'user'], [DoubleQuotedScalarString('admin@%s' % self.hostname)])

        with open(config_file, 'w') as fh:
            new_config = ruamel.yaml.round_trip_dump(config_yml)
            fh.write(new_config)

        self._create_cert_files()

    def _create_cert_files(self):
        """
        Creates certificate for the XMPP server - using the certificate object, global letsencrypt certificate.
        :return: 
        """
        self._find_dirs_if_needed()

        cert_path, key_path = self._get_tls_paths()
        cert_data = open(cert_path).read().strip()
        key_data = open(key_path).read().strip()

        util.safely_remove(self._server_cert_path)
        with util.safe_open(self._server_cert_path, 'w', 0o600) as fh:
            fh.write('%s\n%s\n' % (cert_data, key_data))

        if self._user is None:
            raise errors.InvalidState('Unknown user / group')

        os.chown(self._server_cert_path, self._user, self._group)

    def _ctl_cmd(self, cmd, require_zero_result=True):
        """
        Calls ejabberctl command, returns ret, out, err
        :param cmd: 
        :return: 
        """
        self._find_dirs_if_needed()
        cmd = '%s %s' % (self._ejabberctl, cmd)
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd, cwd=self._root_dir)
        if require_zero_result and ret != 0:
            raise errors.SetupError('Ejabberctl call failed')

        return ret, out, err

    def _config_server(self):
        """
        Server configuration - rosters, groups.
        :return: 
        """
        # Create shared roster group via ejabberctl.
        cmd = 'srg_create %s %s %s %s %s' % (
            util.escape_shell(self._shared_group),
            util.escape_shell(self.hostname),
            util.escape_shell(self._shared_group),
            util.escape_shell(self._shared_group),
            util.escape_shell(self._shared_group))
        self._ctl_cmd(cmd, False)

        cmd = 'srg_user_add \'@all@\' \'\' %s %s' % (self._shared_group, self.hostname)
        self._ctl_cmd(cmd, False)

    def configure(self):
        """
        Configures ejabberd server
        :return: 
        """
        start_system = self.sysconfig.get_start_system()
        if start_system == osutil.START_INITD:
            self.sysconfig.install_initd_svc('ejabberd', script_path=self._bin_initd_script)
        elif start_system == osutil.START_SYSTEMD:
            self.sysconfig.install_systemd_svc('ejabberd', script_path=self._bin_svc_script)
        else:
            raise errors.EnvError('Unknown start system, could not setup ')

        self._config()

        # Configuring via cmdline - we need it running
        self.switch(start=True)

        time.sleep(1)
        self._config_server()

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

    def on_cert_renewed(self):
        """
        Handles certificate renewal
        :return: 
        """
        self.hostname = self.config.hostname
        self.switch(stop=True)
        self._create_cert_files()
        self.switch(start=True)

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
            cmd_exec = 'sudo yum localinstall enablerepo=epel -y %s' % util.escape_shell(archive_path)
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
            base_file = self._file_rpm
        elif pkg == osutil.PKG_APT:
            base_file = self._file_deb
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
                    self._find_dirs()
                    return 0

                finally:
                    if os.path.exists(tmpdir):
                        shutil.rmtree(tmpdir)

        except Exception as e:
            logger.debug('Exception when fetching Ejabberd')
            self.audit.audit_exception(e)
            raise errors.SetupError('Could not install Ejabberd', cause=e)

    def _install_extauth(self):
        """
        Installs external authentication plugin
        :return: 
        """
        url = self._file_extauth
        base_file = 'extauth-nc.tgz'
        try:
            logger.debug('Going to download Ejabberd/extauth')
            tmpdir = util.safe_new_dir('/tmp/ejabberd-extauth-install')
            archive_path = os.path.join(tmpdir, base_file)

            try:
                self.audit.audit_evt('prov-extauth', url=url)
                self._download_file(url, archive_path, attempts=3)
                unpacked_dir = util.untar_get_single_dir(archive_path, self.sysconfig)

                if os.path.exists(self._extauth_path):
                    shutil.rmtree(self._extauth_path)

                shutil.move(unpacked_dir, self._extauth_path)

                # Setup log dir for ext auth
                if os.path.exists(self._extauth_log_dir):
                    util.make_or_verify_dir(self._extauth_log_dir)
                self.sysconfig.chown_recursive(self._extauth_log_dir, self._user, self._group, throw_on_error=False)

            finally:
                if os.path.exists(tmpdir):
                    shutil.rmtree(tmpdir)

            return 0

        except Exception as e:
            logger.debug('Exception when fetching Ejabberd/extauth: %s' % e)
            self.audit.audit_exception(e)
            raise errors.SetupError('Could not install Ejabberd/extauth', cause=e)

    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        ret = self._install(attempts=3)
        if ret != 0:
            raise errors.SetupError('Could not install Ejabberd')

        self._install_extauth()
        return 0






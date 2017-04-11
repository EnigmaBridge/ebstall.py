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
import ebstall.deployers.letsencrypt as letsencrypt
import shutil
import pkg_resources
import nginxparser_eb


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class Nginx(object):
    """
    Nginx server
    
    TODO: edit for ubuntu, has default server in a separate dir, sites-enabled
    """
    SETTINGS_FILE = '/etc/nginx/nginx.conf'

    def __init__(self, sysconfig=None, write_dots=False, audit=None, mysql=None, config=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dots = write_dots
        self.audit = audit
        self.mysql = mysql
        self.config = config
        self.ejbca = None

        self.hostname = 'private-space'
        self.domains = []

        self.nginx_user = 'nginx'
        self.html_root = '/var/www/html'
        self.html_root_old = '/var/www/html'
        self.http_include = '/etc/nginx/conf.d'
        self.site_enabled = None
        self.config_root = None
        self.config_dirty = False

        self.internal_addresses = []  # Addresses allowed to access private.space
        self.cert_dir = None  # certificate directory of LetsEncrypt

    #
    # server.conf reading & modification
    #

    def get_config_file_path(self):
        """
        Returns config file path
        :return: server config file path
        """
        return self.SETTINGS_FILE

    def _load_nginx_config(self):
        """
        Loads configuration file to the model
        :return: 
        """
        cfg_path = self.get_config_file_path()
        if not os.path.exists(cfg_path):
            logger.debug('Nginx config file %s not found' % cfg_path)
            raise errors.SetupError('Nginx configuration file not found')

        logger.debug('Parsing nginx config: %s' % cfg_path)
        with open(cfg_path, 'r') as fh:
            cfg_txt = fh.read()
            cfg_raw = nginxparser_eb.loads(cfg_txt)
            self.config_root = nginxparser_eb.build_model(cfg_raw)
            self._config_parse_test(cfg_txt)

    def _rebuild_cfg_model(self):
        """
        Rebuilds configuration model
        :return: 
        """
        cfg_raw = self.config_root.raw
        self.config_root = nginxparser_eb.build_model(cfg_raw)
        self._config_parse_test()

    def _config_parse_test(self, cfg_txt=None):
        """
        Tests if the config processor understood the configuration well
        by dumping, loading and dumping again. Dumps have to match.
        :return: 
        """

        dumped = nginxparser_eb.dumps(self.config_root.raw)
        if cfg_txt is not None and cfg_txt.strip() != dumped.strip():
            raise errors.EnvError('Nginx config file was not parsed properly')

        parsed2 = nginxparser_eb.loads(dumped)
        dumped2 = nginxparser_eb.dumps(parsed2)
        if dumped.strip() != dumped2.strip():
            raise errors.EnvError('Nginx config file was not parsed properly')

    def load_html_root(self):
        """
        Loads path to the default root
        :return:
        """
        roots = nginxparser_eb.find_in_model(self.config_root, ['http', 'server', 'root'])
        for root in roots:
            self.html_root_old = root.value
            break

        return self.html_root_old

    def _load_config_vars(self):
        """
        Loads basic nginx config vars
        :return: 
        """
        res = nginxparser_eb.find_in_model(self.config_root, ['user'])
        for x in res:
            self.nginx_user = x.value
            break

    def _load_dirs(self):
        """
        Loads nginx directories from config file
        :return: 
        """
        res = nginxparser_eb.find_in_model(self.config_root, ['http', 'include'])
        for x in res:
            path = x.value.strip()
            if path.endswith('*.conf'):
                self.http_include = path[:-7]
            if path.endswith('/*') and 'enabled' in path:
                self.site_enabled = path[:-2]

        if self.http_include is not None:
            if not os.path.exists(self.http_include):
                os.makedirs(self.http_include, mode=0o755)

    def _disable_default_server(self):
        """
        Disables the default server in the configuration
        :return: 
        """
        # Try sites enabled
        if self.site_enabled is not None:
            cand_path = os.path.join(self.site_enabled, 'default')
            util.safely_remove(cand_path)

        # Inspect main config file, find for default servers
        servers = nginxparser_eb.find_in_model(self.config_root, ['http', 'server'])
        for server in servers:
            is_default_server = False
            listens = nginxparser_eb.find_in_model(server, ['listen'])
            for listen in listens:
                if 'default_server' in listen.value:
                    is_default_server = True
                    break

            # Remove from parent raw cfg.
            if is_default_server:
                self.config_root = nginxparser_eb.remove_from_model(self.config_root, server)

        self.flush_config()

    def _get_default_server_hostnames(self, include_local=True):
        """
        Default server hostnames
        :return: 
        """
        hostnames = ['private.space'] if include_local else []

        tmp = list(self.domains)
        if self.hostname is not None:
            tmp += [self.hostname]
        return hostnames + sorted(list(set(tmp)))

    def _get_tls_paths(self):
        """
        Returns chain & key path for TLS or None, None
        :return: keychain path, privkey path
        """
        if self.cert_dir is None:
            logger.debug('Cert dir is none')
            return None, None

        cert_path = os.path.join(self.cert_dir, letsencrypt.LE_CA)
        key_path = os.path.join(self.cert_dir, letsencrypt.LE_PRIVATE_KEY)
        return cert_path, key_path

    def _check_certificates(self):
        """
        Returns True if there is a fullchain.pem certificate and the key in the cert dir
        :return: 
        """
        if self.cert_dir is None:
            logger.debug('Cert dir is none')
            return False

        cert, key = self._get_tls_paths()
        if cert is None or key is None:
            logger.debug('Cert or key is none')
            return False

        if not os.path.exists(cert) or not os.path.exists(key):
            logger.info('Certificate / key are empty: %s, %s' % (cert, key))
            return False

        return True

    def _conf_php_file_handler(self):
        """
        Returns php file handler configuration directive
        :return: 
        """
        perm = ['allow   127.0.0.1;'] + \
               ['allow   %s;' % x for x in self.internal_addresses]

        ret = perm + [
            'fastcgi_split_path_info ^(.+\.php)(/.*)$;',
            'include fastcgi_params;',
            'fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;',
            'fastcgi_param PATH_INFO $fastcgi_path_info;',
            'fastcgi_param HTTPS on;',
            'fastcgi_param modHeadersAvailable true; #Avoid sending the security headers twice',
            'fastcgi_param front_controller_active true;',
            'fastcgi_pass php-handler;',
            'fastcgi_intercept_errors on;',
            'fastcgi_request_buffering off; #Available since nginx 1.7.11']
        return ret

    def _install_default_server(self):
        """
        Installs a default server to the include dir
        :return: 
        """
        if self.http_include is None:
            raise errors.SetupError('HTTP include dir is none')

        path = os.path.join(self.http_include, 'default.conf')
        util.safely_remove(path)

        hostnames = self._get_default_server_hostnames(True)
        with util.safe_open(path, mode='w', chmod=0o644) as fh:
            fh.write('server { \n')
            fh.write('  listen 80 default_server;\n')
            fh.write('  listen [::]:80 default_server;\n')
            fh.write('  root %s;\n' % self.html_root)
            fh.write('  server_name _ %s;\n\n' % (' '.join(hostnames)))

            # Well known serving from the directory
            fh.write('  location /.well-known {\n')
            fh.write('    allow all;\n')
            fh.write('  }\n\n')

            # If we have https, do the redirect to https variant
            if self._check_certificates():
                fh.write('  location / {\n')
                fh.write('    return 302 https://%s$request_uri;\n' % self.hostname)
                fh.write('  }\n\n')

            else:
                # Root
                fh.write('  location / {\n')
                fh.write('    try_files $uri $uri/ =404;\n')
                fh.write('    allow   127.0.0.1;\n')
                for internal in self.internal_addresses:
                    fh.write('    allow   %s;\n' % internal)

                fh.write('    deny    all;\n')
                fh.write('  }\n')

                # PHP files
                fh.write('  location ~ \.php$ {\n')
                fh.write('    ' + ('\n    '.join(self._conf_php_file_handler())))
                fh.write('\n')
                fh.write('  }\n\n')

            fh.write('}\n\n')

    def _install_secure_default_server(self):
        """
        HTTPS variant of the default server
        :return: 
        """
        if not self._check_certificates():
            logger.debug('Not going to install secure server - cert fail')
            return

        path = os.path.join(self.http_include, 'default-tls.conf')
        util.safely_remove(path)

        hostnames = self._get_default_server_hostnames(False)
        cert_path, key_path = self._get_tls_paths()
        with util.safe_open(path, mode='w', chmod=0o644) as fh:
            fh.write('server { \n')
            fh.write('  listen 443 ssl;\n')
            fh.write('  listen [::]:443 ssl;\n')
            fh.write('  root %s;\n' % self.html_root)
            fh.write('  server_name _ %s;\n\n' % (' '.join(hostnames)))
            fh.write('  ssl_certificate %s;\n' % cert_path)
            fh.write('  ssl_certificate_key %s;\n\n' % key_path)

            fh.write('  add_header X-Content-Type-Options nosniff;\n')
            fh.write('  add_header X-Frame-Options "SAMEORIGIN";\n')
            fh.write('  add_header X-XSS-Protection "1; mode=block";\n')
            fh.write('  add_header X-Robots-Tag none;\n')
            fh.write('  add_header X-Download-Options noopen;\n')
            fh.write('  add_header X-Permitted-Cross-Domain-Policies none;\n\n')

            # LetsEncrypt validation
            fh.write('  location /.well-known {\n')
            fh.write('      allow all;\n')
            fh.write('   }\n\n')

            # Root access only for internals
            fh.write('  location / {\n')
            fh.write('    try_files $uri $uri/ /index.php?$query_string;\n')
            fh.write('    allow   127.0.0.1;\n')

            for internal in self.internal_addresses:
                fh.write('    allow   %s;\n' % internal)

            fh.write('  }\n\n')

            # PHP files
            fh.write('  location ~ \.php$ {\n')
            fh.write('    ' + ('\n    '.join(self._conf_php_file_handler())))
            fh.write('\n')
            fh.write('  }\n\n')

            # Robots
            fh.write('  location /robots.txt {\n')
            fh.write('    allow all;\n')
            fh.write('    log_not_found off;\n')
            fh.write('    access_log off;\n')
            fh.write('  }\n')
            fh.write('}\n\n')

    def add_php_index(self):
        """
        Adds index.php to the index list
        :return: 
        """
        res = nginxparser_eb.find_in_model(self.config_root, ['http', 'index'])
        for x in res:
            vals = x.value
            if 'index.php' in vals:
                return

            # Update
            x.value += ' index.php'
            x.raw[1] += ' index.php'
            self.config_dirty = True
            break
        self.flush_config()

    def add_php_handler(self):
        """
        Adds php handler configuration to the http_include
        :return: 
        """
        if self.http_include is None:
            raise errors.EnvError('Nginx HTTP include directory does not exist')

        php_path = os.path.join(self.http_include, 'php-fpm.conf')
        util.safely_remove(php_path)
        with util.safe_open(php_path, mode='w', chmod=0o755) as fh:
            fh.write('# PHP upstream handler\n')
            fh.write('upstream php-handler {\n')
            fh.write('  server 127.0.0.1:9000;\n')
            fh.write('  #server unix:/var/run/php5-fpm.sock;\n')
            fh.write('}\n\n')

    def flush_config(self):
        """
        Flushed dirty nginx configuration to the file
        :return: 
        """
        if not self.config_dirty:
            return

        dump = nginxparser_eb.dumps(self.config_root.raw)
        with open(self.get_config_file_path(), 'w') as fh:
            fh.write(dump)

        self.config_dirty = False

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

    def load_configuration(self):
        """
        Loads configuration, base init. 
        Loads variables needed by other modules, e.g., PHP (nginx user).
        :return: 
        """
        self._load_nginx_config()
        self._load_config_vars()
        self._load_dirs()
        self.flush_config()

    def configure_server(self):
        """
        Perform base server configuration.
        :return: True if file was changed
        """

        self.load_html_root()
        if self.html_root is None:
            raise errors.SetupError('Could not determine default root of the Nginx server')

        # Disable the default server, create a custom one.
        self._disable_default_server()
        self._install_default_server()
        self._install_secure_default_server()

        # PHP integration
        self.add_php_handler()
        self.add_php_index()
        self.flush_config()

        if os.path.exists(self.html_root):
            util.dir_backup(self.html_root, backup_dir='/tmp')
            shutil.rmtree(self.html_root)

        util.make_or_verify_dir(self.html_root)
        return 0

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



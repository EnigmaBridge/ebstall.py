#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import util
from sarge import run, Capture, Feeder
from ebclient.eb_utils import EBUtils
from datetime import datetime
import time
import sys
import types
import errors
import subprocess
import shutil
import re
import json
import certbot_external_auth as cba


__author__ = 'dusanklinec'


LE_PRIVATE_KEY = 'privkey.pem'
LE_CERT = 'cert.pem'
LE_CA = 'fullchain.pem'


class LetsEncryptToJks(object):
    """
    Imports Lets encrypt certificate to Java Key Store (JKS)
    """
    PRIVATE_KEY = LE_PRIVATE_KEY
    CERT = LE_CERT
    CA = LE_CA
    TMP_P12 = '/tmp/tmpcert.p12'
    OPENSSL_LOG = '/tmp/openssl.log'
    KEYTOOL_LOG = '/tmp/keytool.log'

    def __init__(self, cert_dir=None, jks_path=None, jks_alias='tomcat', password='password', keytool_path=None, print_output=False, *args, **kwargs):
        self.cert_dir = cert_dir
        self.jks_path = jks_path
        self.jks_alias = jks_alias
        self.password = password
        self.keytool_path = keytool_path
        self.print_output = print_output

        self.priv_file = None
        self.cert_file = None
        self.ca_file = None

    def get_keytool(self):
        return 'keytool' if self.keytool_path is None else self.keytool_path

    def print_error(self, msg):
        if self.print_output:
            sys.stderr.write(msg)

    def del_entry(self, alias=None, password=None, keystore=None):
        """
        keytool -delete -alias mydomain -keystore keystore.jks
        """
        keytool = self.get_keytool()
        if not util.exe_exists(keytool):
            self.print_error('Error, keytool command not found')
            return 4

        alias = alias if alias is not None else self.jks_alias
        password = password if password is not None else self.password
        keystore = keystore if keystore is not None else self.jks_path

        cmd = 'sudo -E -H %s -delete -alias "%s" -keystore "%s" -srcstorepass "%s"' \
              % (keytool, alias, keystore, password)

        log_obj = self.KEYTOOL_LOG
        ret, out, err = util.cli_cmd_sync(cmd, log_obj=log_obj, write_dots=self.print_output)
        if ret != 0:
            self.print_error('\nKeyTool command failed.')
            self.print_error('For more information please refer to the log file: %s' % log_obj)
            return 6
        return 0

    def check_files(self):
        self.priv_file = os.path.join(self.cert_dir, self.PRIVATE_KEY)
        self.cert_file = os.path.join(self.cert_dir, self.CERT)
        self.ca_file = os.path.join(self.cert_dir, self.CA)

        if not os.path.exists(self.priv_file):
            return 1

        if not os.path.exists(self.cert_file):
            return 2

        if not os.path.exists(self.ca_file):
            return 3

        return 0

    def convert(self):
        file_check = self.check_files()
        if file_check == 1:
            self.print_error('Error, private key not found at %s\n' % self.priv_file)
            return 1
        elif file_check == 2:
            self.print_error('Error, cert not found at %s\n' % self.cert_file)
            return 2
        elif file_check == 3:
            self.print_error('Error, fullchain file not found at %s\n' % self.ca_file)
            return 3

        keytool = self.get_keytool()
        if not util.exe_exists(keytool):
            self.print_error('Error, keytool command not found')
            return 4

        openssl = 'openssl'
        if not util.exe_exists(openssl):
            self.print_error('Error, openssl command not found')
            return 5

        # 1. step - create p12 file
        p12_file, p12_name = util.unique_file(self.TMP_P12, mode=0o600)
        p12_file.close()

        try:
            cmd = 'sudo -E -H %s pkcs12 -export -out "%s" ' \
                  ' -password pass:"%s" ' \
                  ' -inkey "%s" ' \
                  ' -in "%s" ' \
                  ' -certfile "%s" ' \
                  ' -name "%s" ' % (openssl, p12_name, self.password, self.priv_file, self.cert_file, self.ca_file, self.jks_alias)

            log_obj = self.OPENSSL_LOG
            ret, out, err = util.cli_cmd_sync(cmd, log_obj=log_obj, write_dots=self.print_output)
            if ret != 0:
                self.print_error('\nOpenSSL command failed.')
                self.print_error('For more information please refer to the log file: %s' % log_obj)
                return 6

            # 2. step - create JKS
            cmd = 'sudo -E -H %s -importkeystore -deststorepass "%s" ' \
                  ' -destkeypass "%s" ' \
                  ' -destkeystore "%s" ' \
                  ' -srckeystore "%s" ' \
                  ' -srcstoretype PKCS12 ' \
                  ' -srcstorepass "%s" ' \
                  ' -alias "%s" ' % (keytool, self.password, self.password, self.jks_path, p12_name, self.password, self.jks_alias)

            log_obj = self.KEYTOOL_LOG
            ret, out, err = util.cli_cmd_sync(cmd, log_obj=log_obj, write_dots=self.print_output)
            if ret != 0:
                self.print_error('\nKeytool command failed.')
                self.print_error('For more information please refer to the log file: %s' % log_obj)
                return 7

            return 0

        finally:
            if os.path.exists(p12_name):
                    os.remove(p12_name)


class LetsEncryptManualDns(object):
    """
    Manual DNS LetsEncrypt verifier
    """

    def __init__(self, email=None, domains=None, print_output=False, on_domain_challenge=None,
                 cmd=None, cmd_exec=None, log_obj=None, debug=False, *args, **kwargs):

        self.email = email
        self.domains = domains
        self.print_output = print_output
        self.debug = debug

        self.cmd = cmd
        self.cmd_exec = cmd_exec
        self.log_obj = log_obj

        self.p = None
        self.on_domain_challenge = on_domain_challenge
        self.manual_dns_last_validation = None
        self.manual_dns_last_domain = None
        self.manual_dns_last_token = None
        self.manual_dns_report = None

    def answer_manual_dns_out(self, out, feeder, p, *args, **kwargs):
        return self.answer_manual_dns(out, feeder, p, err=False)

    def answer_manual_dns_err(self, out, feeder, p, *args, **kwargs):
        return self.answer_manual_dns(out, feeder, p, err=True)

    def answer_manual_dns(self, out, feeder, p, err=False, *args, **kwargs):
        self.p = p

        if self.print_output:
            sys.stderr.write('.')
            sys.stderr.flush()

        if err:
            return

        out = out.strip()
        if len(out) == 0:
            return

        def done():
            feeder.feed('\n')

        try:
            json_obj = json.loads(out)
        except:
            return

        if cba.FIELD_CMD not in json_obj:
            raise ValueError('Could not process json command: %s' % out)
        cmd = json_obj[cba.FIELD_CMD]
        if cmd == cba.COMMAND_PERFORM:
            self.manual_dns_last_validation = json_obj
            self.manual_dns_last_token = json_obj[cba.FIELD_VALIDATION]
            self.manual_dns_last_domain = json_obj[cba.FIELD_TXT_DOMAIN]
            self.on_domain_challenge(domain=self.manual_dns_last_domain, token=self.manual_dns_last_token,
                                     mdns=self, p=p, done=done, abort=self.abort)

        elif cmd == 'report':
            pass

    def abort(self):
        if self.p is not None:
            self.p.commands[0].terminate()

    def print_error(self, msg):
        if self.print_output:
            sys.stderr.write(msg)

    def start(self):
        """
        Trigger the new verification
        """
        ret, out, err = util.cli_cmd_sync(self.cmd_exec, log_obj=self.log_obj, write_dots=self.print_output,
                                          on_err=self.answer_manual_dns_err, on_out=self.answer_manual_dns_out)
        if ret != 0:
            self.print_error('\nCertbot command failed: %s\n' % self.cmd_exec)
            self.print_error('For more information please refer to the log file: %s' % self.log_obj)

        return ret, out, err


class LetsEncrypt(object):
    """
    LetsEncrypt integration
    """

    PORT = 443
    CERTBOT_PATH = '/usr/local/bin/certbot'
    LE_CERT_PATH = '/etc/letsencrypt/live'
    CERTBOT_LOG = '/tmp/certbot.log'
    PRIVATE_KEY = LE_PRIVATE_KEY
    CERT = LE_CERT
    CA = LE_CA
    FALLBACK_EMAIL = 'letsencrypt_support@enigmabridge.com'

    def __init__(self, email=None, domains=None, print_output=False, staging=False, debug=False, *args, **kwargs):
        self.email = email
        self.domains = domains
        self.print_output = print_output
        self.staging = staging
        self.debug = debug

    def certonly(self, email=None, domains=None, expand=False):
        if email is not None:
            self.email = email
        if domains is not None:
            self.domains = domains

        email = self.email
        if (self.email is None or len(self.email) == 0) \
                and self.FALLBACK_EMAIL is not None and len(self.FALLBACK_EMAIL) > 0:
            email = self.FALLBACK_EMAIL

        cmd = self.get_standalone_cmd(self.domains, email=email, expand=expand, staging=self.staging)
        cmd_exec = 'sudo -E -H %s %s' % (self.CERTBOT_PATH, cmd)
        log_obj = self.CERTBOT_LOG

        ret, out, err = util.cli_cmd_sync(cmd_exec, log_obj=log_obj, write_dots=self.print_output)
        if ret != 0:
            self.print_error('\nCertbot command failed: %s\n' % cmd_exec)
            self.print_error('For more information please refer to the log file: %s' % log_obj)

        return ret, out, err

    def manual_dns(self, email=None, domains=None, expand=True, on_domain_challenge=None):
        if email is not None:
            self.email = email
        if domains is not None:
            self.domains = domains

        email = self.email
        if (self.email is None or len(self.email) == 0) \
                and self.FALLBACK_EMAIL is not None and len(self.FALLBACK_EMAIL) > 0:
            email = self.FALLBACK_EMAIL

        cmd = self.get_manual_dns(self.domains, email=email, expand=expand, staging=self.staging)
        cmd_exec = 'sudo -E -H %s %s' % (self.CERTBOT_PATH, cmd)
        log_obj = self.CERTBOT_LOG

        mdns = LetsEncryptManualDns(email=email, domains=self.domains, on_domain_challenge=on_domain_challenge,
                                    cmd=cmd, cmd_exec=cmd_exec, log_obj=log_obj)
        return mdns

    def renew(self):
        cmd = self.get_renew_cmd()
        cmd_exec = 'sudo -E -H %s %s' % (self.CERTBOT_PATH, cmd)
        log_obj = self.CERTBOT_LOG

        ret, out, err = util.cli_cmd_sync(cmd_exec, log_obj=log_obj, write_dots=self.print_output)
        if ret != 0 and self.print_output:
            self.print_error('\nCertbot command failed: %s\n' % cmd_exec)
            self.print_error('For more information please refer to the log file: %s' % log_obj)

        return ret, out, err

    def get_certificate_dir(self, domain=None):
        if domain is None:
            return self.LE_CERT_PATH
        else:
            return os.path.join(self.LE_CERT_PATH, domain)

    def get_cert_paths(self, cert_dir=None, domain=None):
        if domain is not None:
            cert_dir = self.get_certificate_dir(domain)
        if cert_dir is None:
            raise ValueError('Either cert_dir or domain has to be filled')

        priv_file = os.path.join(cert_dir, self.PRIVATE_KEY)
        cert_file = os.path.join(cert_dir, self.CERT)
        ca_file = os.path.join(cert_dir, self.CA)
        return priv_file, cert_file, ca_file

    def is_certificate_ready(self, cert_dir=None, domain=None):
        priv_file, cert_file, ca_file = self.get_cert_paths(cert_dir=cert_dir, domain=domain)
        if not os.path.exists(priv_file):
            return 1
        elif not os.path.exists(cert_file):
            return 2
        elif not os.path.exists(ca_file):
            return 3
        else:
            return 0

    def test_certificate_for_renew(self, cert_dir=None, domain=None, renewal_before=60*60*24*30):
        """Tries to load PEM certificate and check not after"""
        priv_file, cert_file, ca_file = self.get_cert_paths(cert_dir=cert_dir, domain=domain)
        if not os.path.exists(cert_file):
            return 1

        try:
            x509_pem = None
            with open(cert_file, 'r') as hnd:
                x509_pem = hnd.read()

            if x509_pem is None or len(x509_pem) == 0:
                return 2

            x509 = util.load_x509(x509_pem)
            if x509 is None:
                return 3

            not_after = x509.not_valid_after
            utc_now = datetime.utcnow()

            # Already expired?
            if not_after <= utc_now:
                return 4

            delta = not_after - utc_now
            delta_sec = delta.total_seconds()

            if delta_sec < renewal_before:
                return 5

            return 0
        except:
            return 100

    def test_port_open(self, ip=None, timeout=5, attempts=3):
        """
        Tests if 443 port is open on the local host - required for Certbot to work - LetsEncrypt
        verification.
        For this test a dummy TCP server is started.

        :param ip:
        :param timeout:
        :param attempts:
        :return:
        """
        server = util.EchoUpTCPServer(('0.0.0.0', self.PORT))
        with server.start():
            time.sleep(1.5)
            return util.test_port_open(ip, self.PORT, timeout=timeout, attempts=attempts)
        pass

    def print_error(self, msg):
        if self.print_output:
            sys.stderr.write(msg)

    @staticmethod
    def get_standalone_cmd(domain, email=None, expand=False, staging=False):
        cmd_email_part = LetsEncrypt.get_email_cmd(email)

        domains = domain if isinstance(domain, types.ListType) else [domain]
        domains = ['"%s"' % x.strip() for x in domains]
        cmd_domains_part = ' -d ' + (' -d '.join(domains))

        cmd_expand_part = '' if not expand else ' --expand '
        cmd_staging = LetsEncrypt.get_staging_cmd(staging)

        cmd = 'certonly --standalone --text -n --agree-tos %s %s %s %s' \
              % (cmd_email_part, cmd_expand_part, cmd_staging, cmd_domains_part)
        return cmd

    @staticmethod
    def get_manual_dns(domain, email=None, expand=True, staging=False):
        """
        Non-interactive mode is not yet supported with the manual authenticator.

        :param domain:
        :param email:
        :param expand:
        :return:
        """
        cmd_email_part = LetsEncrypt.get_email_cmd(email)

        domains = domain if isinstance(domain, types.ListType) else [domain]
        domains = ['"%s"' % x.strip() for x in domains]
        cmd_domains_part = ' -d ' + (' -d '.join(domains))

        cmd_expand_part = '' if not expand else ' --expand --renew-by-default '
        cmd_staging = LetsEncrypt.get_staging_cmd(staging)

        cmd = 'certonly --text --agree-tos ' \
              '-a certbot-external-auth:out ' \
              '--certbot-external-auth:out-public-ip-logging-ok ' \
              '--preferred-challenges dns %s %s %s %s' % \
              (cmd_email_part, cmd_expand_part, cmd_staging,  cmd_domains_part)
        return cmd

    @staticmethod
    def get_renew_cmd():
        return 'renew -n'

    @staticmethod
    def get_email_cmd(email):
        email = email if email is not None else ''
        email = email.strip()

        cmd = '--register-unsafely-without-email'
        if len(email) > 0:
            cmd = '--email ' + email
        return cmd

    @staticmethod
    def get_staging_cmd(staging=False):
        if staging:
            return ' --staging '
        else:
            return ' '



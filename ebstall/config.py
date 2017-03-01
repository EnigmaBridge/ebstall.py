#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import functools
import collections
import logging
from consts import *
from errors import *
from ebclient.eb_configuration import Endpoint
from ebclient.registration import *


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class EBEndpoint(Endpoint):
    """
    Extends normal endpoint, with added reference to the configuration
    """
    def __init__(self, scheme=None, host=None, port=None, server=None, *args, **kwargs):
        super(EBEndpoint, self).__init__(
            scheme=scheme,
            host=host,
            port=port)
        self.server = server


class Config(object):
    """Configuration object, handles file read/write"""

    def __init__(self, json_db=None, eb_config=None, *args, **kwargs):
        self.json = json_db
        self.eb_config = eb_config

        pass

    @classmethod
    def from_json(cls, json_string):
        return cls(json_db=json.loads(json_string, object_pairs_hook=collections.OrderedDict))

    @classmethod
    def from_file(cls, file_name):
        with open(file_name, 'r') as f:
            read_lines = [x.strip() for x in f.read().split('\n')]
            lines = []
            for line in read_lines:
                if line.startswith('//'):
                    continue
                lines.append(line)

            return Config.from_json('\n'.join(lines))

    def ensure_config(self):
        if self.json is None:
            self.json = collections.OrderedDict()
        if 'config' not in self.json:
            self.json['config'] = collections.OrderedDict()

    def has_nonempty_config(self):
        return self.json is not None and 'config' in self.json and len(self.json['config']) > 0

    def get_config(self, key, default=None):
        if not self.has_nonempty_config():
            return default
        return self.json['config'][key] if key in self.json['config'] else default

    def set_config(self, key, val):
        self.ensure_config()
        self.json['config'][key] = val

    def has_identity(self):
        return self.username is not None

    def has_apikey(self):
        return self.apikey is not None

    def to_string(self):
        return json.dumps(self.json, indent=2) if self.has_nonempty_config() else ""

    def resolve_endpoint(self, purpose=SERVER_PROCESS_DATA, protocol=PROTOCOL_HTTPS, environment=None, *args, **kwargs):
        """
        Resolves required endpoint from the configuration according to the parameters
        :param purpose:
        :param protocol:
        :return:
        """
        if not self.has_nonempty_config() or self.servers is None:
            raise ValueError('Configuration has no servers')

        candidate_list = []
        for server in self.servers:
            endpoint_key = 'useEndpoints'
            if purpose == SERVER_ENROLLMENT:
                endpoint_key = 'enrolEndpoints'
            elif purpose == SERVER_REGISTRATION:
                endpoint_key = 'registerEndpoints'
            elif purpose != SERVER_PROCESS_DATA:
                raise ValueError('Endpoint purpose unknown')

            if endpoint_key not in server:
                continue
            if environment is not None and server['environment'] != environment:
                continue

            endpoints = server[endpoint_key]
            for endpoint in endpoints:
                if protocol is not None and endpoint['protocol'] != protocol:
                    continue

                # Construct a candidate
                candidate = EBEndpoint(scheme=endpoint['protocol'],
                                       host=server['fqdn'],
                                       port=endpoint['port'],
                                       server=server)

                candidate_list.append(candidate)
            pass

        if len(candidate_list) == 0:
            raise NoSuchEndpoint('No such endpoint found')

        return candidate_list[0], candidate_list

    def get_le_method(self, le_method=None, default=None):
        """
        Decides which LetsEncrypt domain verification method to use w.r.t. current settings
        :param le_method:
        :return:
        """
        if le_method is not None:
            return le_method
        if self.is_private_network and self.le_preferred_verification == LE_VERIFY_TLSSNI:
            logger.warning('Conflicting LE settings - private network && TLS SNI')
        if self.is_private_network:
            return LE_VERIFY_DNS
        if self.le_preferred_verification is not None:
            return self.le_preferred_verification
        if default is not None:
            return default
        return LE_VERIFY_DEFAULT

    # email
    @property
    def email(self):
        return self.get_config('email')

    @email.setter
    def email(self, val):
        self.set_config('email', val)

    # username
    @property
    def username(self):
        return self.get_config('username')

    @username.setter
    def username(self, val):
        self.set_config('username', val)

    # password
    @property
    def password(self):
        return self.get_config('password')

    @password.setter
    def password(self, val):
        self.set_config('password', val)

    # apikey
    @property
    def apikey(self):
        return self.get_config('apikey')

    @apikey.setter
    def apikey(self, val):
        self.set_config('apikey', val)

    # env
    @property
    def env(self):
        return self.get_config('env')

    @env.setter
    def env(self, val):
        self.set_config('env', val)

    # process endpoint
    @property
    def servers(self):
        return self.get_config('servers')

    @servers.setter
    def servers(self, val):
        self.set_config('servers', val)

    # Time the configuration was generated
    @property
    def generated_time(self):
        return self.get_config('generated_time')

    @generated_time.setter
    def generated_time(self, val):
        self.set_config('generated_time', val)

    # NS domain
    @property
    def nsdomain(self):
        return self.get_config('nsdomain')

    @nsdomain.setter
    def nsdomain(self, val):
        self.set_config('nsdomain', val)

    # DNS domains
    @property
    def domains(self):
        return self.get_config('domains')

    @domains.setter
    def domains(self, val):
        self.set_config('domains', val)

    # EJBCA hostname
    @property
    def ejbca_hostname(self):
        return self.get_config('ejbca_hostname')

    @ejbca_hostname.setter
    def ejbca_hostname(self, val):
        self.set_config('ejbca_hostname', val)

    # EJBCA LE domains
    @property
    def ejbca_domains(self):
        return self.get_config('ejbca_domains')

    @ejbca_domains.setter
    def ejbca_domains(self, val):
        self.set_config('ejbca_domains', val)

    # EJBCA database type
    @property
    def ejbca_db_type(self):
        return self.get_config('ejbca_db_type')

    @ejbca_db_type.setter
    def ejbca_db_type(self, val):
        self.set_config('ejbca_db_type', val)

    # MySQL root password for the initialisation
    @property
    def mysql_root_password(self):
        return self.get_config('mysql_root_password')

    @mysql_root_password.setter
    def mysql_root_password(self, val):
        self.set_config('mysql_root_password', val)

    # EJBCA key store password
    @property
    def ejbca_jks_password(self):
        return self.get_config('ejbca_jks_password')

    @ejbca_jks_password.setter
    def ejbca_jks_password(self, val):
        self.set_config('ejbca_jks_password', val)

    # EJBCA database password
    @property
    def ejbca_db_password(self):
        return self.get_config('ejbca_db_password')

    @ejbca_db_password.setter
    def ejbca_db_password(self, val):
        self.set_config('ejbca_db_password', val)

    # EJBCA master key store password for VPN user credentials encryption
    @property
    def ejbca_p12master_password(self):
        return self.get_config('ejbca_p12master_password')

    @ejbca_p12master_password.setter
    def ejbca_p12master_password(self, val):
        self.set_config('ejbca_p12master_password', val)

    # EJBCA custom hostname flag
    @property
    def ejbca_hostname_custom(self):
        return self.get_config('ejbca_hostname_custom', default=False)

    @ejbca_hostname_custom.setter
    def ejbca_hostname_custom(self, val):
        self.set_config('ejbca_hostname_custom', val)

    # Last public IPV4 used by EJBCA domain
    @property
    def last_ipv4(self):
        return self.get_config('last_ipv4')

    @last_ipv4.setter
    def last_ipv4(self, val):
        self.set_config('last_ipv4', val)

    # Last private IPv4
    @property
    def last_ipv4_private(self):
        return self.get_config('last_ipv4_private')

    @last_ipv4_private.setter
    def last_ipv4_private(self, val):
        self.set_config('last_ipv4_private', val)

    # VPC ?
    @property
    def is_private_network(self):
        return self.get_config('is_private_network', default=False)

    @is_private_network.setter
    def is_private_network(self, val):
        self.set_config('is_private_network', val)

    # Preferred LetsEncrypt verification ?
    @property
    def le_preferred_verification(self):
        return self.get_config('le_preferred_verification')

    @le_preferred_verification.setter
    def le_preferred_verification(self, val):
        self.set_config('le_preferred_verification', val)

    # Was VPN installed
    @property
    def vpn_installed(self):
        return self.get_config('vpn_installed')

    @vpn_installed.setter
    def vpn_installed(self, val):
        self.set_config('vpn_installed', val)

    # process endpoint
    @property
    def endpoint_process(self):
        return self.resolve_endpoint(SERVER_PROCESS_DATA, PROTOCOL_HTTPS)

    # enroll endpoint
    @property
    def endpoint_enroll(self):
        return self.resolve_endpoint(SERVER_ENROLLMENT, PROTOCOL_HTTPS)

    # 2-stage registration started previously, now waiting...
    @property
    def two_stage_registration_waiting(self):
        return self.get_config('two_stage_registration_waiting', default=False)

    @two_stage_registration_waiting.setter
    def two_stage_registration_waiting(self, val):
        self.set_config('two_stage_registration_waiting', val)

    # client-id from the registration process
    @property
    def client_id(self):
        return self.get_config('client_id', default=None)

    @client_id.setter
    def client_id(self, val):
        self.set_config('client_id', val)

    # p12 otp token
    @property
    def p12_otp_superadmin(self):
        return self.get_config('p12_otp_superadmin', default=None)

    @p12_otp_superadmin.setter
    def p12_otp_superadmin(self, val):
        self.set_config('p12_otp_superadmin', val)


class EBSettings(object):
    """
    General EB settings - type of the machine, profile (AMI, AWS, bare, ...)
    """

    def __init__(self, json_db=None, eb_config=None, *args, **kwargs):
        self.json = json_db
        self.eb_config = eb_config

    @classmethod
    def from_json(cls, json_string):
        return cls(json_db=json.loads(json_string, object_pairs_hook=collections.OrderedDict))

    @classmethod
    def from_file(cls, file_name):
        with open(file_name, 'r') as f:
            read_lines = [x.strip() for x in f.read().split('\n')]
            lines = []
            for line in read_lines:
                if line.startswith('//'):
                    continue
                lines.append(line)

            return EBSettings.from_json('\n'.join(lines))

    def ensure_config(self):
        if self.json is None:
            self.json = collections.OrderedDict()
        if 'config' not in self.json:
            self.json['config'] = collections.OrderedDict()

    def has_nonempty_config(self):
        return self.json is not None and 'config' in self.json and len(self.json['config']) > 0

    def get_config(self, key, default=None):
        if not self.has_nonempty_config():
            return default
        return self.json['config'][key] if key in self.json['config'] else default

    def set_config(self, key, val):
        self.ensure_config()
        self.json['config'][key] = val

    # user_reg_type ?
    @property
    def user_reg_type(self):
        return self.get_config('user_reg_type', default=None)

    @user_reg_type.setter
    def user_reg_type(self, val):
        self.set_config('user_reg_type', val)

    # user_reg_token
    @property
    def user_reg_token(self):
        return self.get_config('user_reg_token', default=None)

    @user_reg_token.setter
    def user_reg_token(self, val):
        self.set_config('user_reg_token', val)

    # EB API token ?
    @property
    def api_token(self):
        return self.get_config('api_token', default=None)

    @api_token.setter
    def api_token(self, val):
        self.set_config('api_token', val)

    # env
    @property
    def env(self):
        return self.get_config('env')

    @env.setter
    def env(self, val):
        self.set_config('env', val)

    # EJBCA database type
    @property
    def ejbca_db_type(self):
        return self.get_config('ejbca_db_type')

    @ejbca_db_type.setter
    def ejbca_db_type(self, val):
        self.set_config('ejbca_db_type', val)

    # MySQL root password for the initialisation
    @property
    def mysql_root_password(self):
        return self.get_config('mysql_root_password')

    @mysql_root_password.setter
    def mysql_root_password(self, val):
        self.set_config('mysql_root_password', val)

    # JBOSS home
    @property
    def jboss_home(self):
        return self.get_config('jboss_home')

    @jboss_home.setter
    def jboss_home(self, val):
        self.set_config('jboss_home', val)

    # EJBCA home
    @property
    def ejbca_home(self):
        return self.get_config('ejbca_home')

    @ejbca_home.setter
    def ejbca_home(self, val):
        self.set_config('ejbca_home', val)


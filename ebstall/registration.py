#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from config import Config
from core import Core
from errors import *
import requests
import util
import re
import errors
import consts
import OpenSSL
import json
import base64
from audit import AuditManager
from datetime import datetime
from ebclient.eb_configuration import *
from ebclient.eb_registration import *
from ebclient.registration import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


class InfoLoader(object):
    """
    Loads information from the system
    """

    AMI_KEY_ID = 'ami-id'
    AMI_KEY_INSTANCE_ID = 'instance-id'
    AMI_KEY_INSTANCE_TYPE = 'instance-type'
    AMI_KEY_PLACEMENT = 'placement'
    AMI_KEY_PRODUCT_CODES = 'product-codes'
    AMI_KEY_PUBLIC_IP = 'public-ipv4'
    AMI_KEY_LOCAL_IP = 'local-ipv4'
    AMI_KEY_PUBLIC_HOSTNAME = 'public-hostname'

    AMI_KEYS = [AMI_KEY_ID, AMI_KEY_INSTANCE_ID, AMI_KEY_INSTANCE_TYPE, AMI_KEY_PLACEMENT, AMI_KEY_PRODUCT_CODES,
                AMI_KEY_PUBLIC_IP, AMI_KEY_LOCAL_IP, AMI_KEY_PUBLIC_HOSTNAME]

    def __init__(self, audit=None, sysconfig=None, *args, **kwargs):
        self.ami_id = None
        self.ami_instance_id = None
        self.ami_instance_type = None
        self.ami_placement = None
        self.ami_product_code = None
        self.ami_results = None
        self.ami_public_ip = None
        self.ami_local_ip = None
        self.ami_public_hostname = None
        self.ec2_metadata_executable = None
        self.public_ip = None
        self.audit = audit
        self.sysconfig = sysconfig

    def env_check(self):
        for candidate in consts.EC2META_FILES:
            if util.exe_exists(candidate):
                self.ec2_metadata_executable = candidate
        if self.ec2_metadata_executable is None:
            raise EnvError('ec2-metadata executable was not found')

    def _load_ipfy(self, attempts=3):
        return util.determine_public_ip(attempts=attempts, audit=self.audit)

    def _load_ip_eb(self, attempts=3):
        return util.determine_public_ip_eb(attempts=attempts, audit=self.audit)

    def load(self):
        self.env_check()

        # removed options:
        # -o local ip
        # -c product codes
        cmd = [self.ec2_metadata_executable] + ('-a -i -t -z -v -p -o'.split(' '))
        ret, out, err = self.sysconfig.cli_cmd_sync(cmd)

        lines = [x.strip() for x in out]
        self.ami_results = {}
        for line in lines:
            if len(line) == 0:
                continue

            match = re.match(r'^\s*([a-zA-Z0-9-\s]+?)\s*:(.+)\s*$', line, re.I)
            if match is None:
                continue

            c_key = match.group(1).strip()
            c_val = match.group(2).strip()
            self.ami_results[c_key] = c_val

            if c_key == self.AMI_KEY_ID:
                self.ami_id = c_val
            elif c_key == self.AMI_KEY_INSTANCE_ID:
                self.ami_instance_id = c_val
            elif c_key == self.AMI_KEY_INSTANCE_TYPE:
                self.ami_instance_type = c_val
            elif c_key == self.AMI_KEY_PLACEMENT:
                self.ami_placement = c_val
            elif c_key == self.AMI_KEY_PRODUCT_CODES:
                self.ami_product_code = c_val
            elif c_key == self.AMI_KEY_LOCAL_IP:
                self.ami_local_ip = c_val
            elif c_key == self.AMI_KEY_PUBLIC_IP:
                self.ami_public_ip = c_val
            elif c_key == self.AMI_KEY_PUBLIC_HOSTNAME:
                self.ami_public_hostname = c_val

        # load public IP
        self.public_ip = self._load_ip_eb()
        if self.public_ip is None:
            self.public_ip = self._load_ipfy()


class EBRegAuth(object):
    """
    EnigmaBridge authentication method
    https://api.enigmabridge.com/api/?json#client-endpoint-restful-api

    Used when creating a new EnigmaBridge user. User may need to authenticate to the server
    he has access to creating a new EB users or to prove he is not a bot.
    One such auth method is email verification.
    """

    def __init__(self, method=None, init_needed=False, init_data=None, *args, **kwargs):
        """
        Initializes new Auth method for EB API.
        :param method: auth method name
        :param bool init_needed: if true new user creation requires some kind of authentication from the user (manual
         intervention)
        :param init_data: initialization data used for new authentication.
        :param args:
        :param kwargs:
        """
        self.method = method
        self.init_needed = init_needed
        self.init_data = init_data


class Registration(object):
    """
    Takes care about EnigmaBridge registration process
    """
    def __init__(self, email=None, eb_config=None, config=None, debug=False, eb_settings=None, audit=None,
                 sysconfig=None, *args, **kwargs):
        self.email = email
        self.debug = debug
        self.eb_config = eb_config
        self.config = config
        self.eb_settings = eb_settings
        self.user_reg_type = None
        self.audit = audit if audit is not None else AuditManager(disabled=True)
        self.sysconfig = sysconfig

        self.key = None
        self.crt = None
        self.key_path = None
        self.crt_path = None

        self.crt_pem = None
        self.key_pem = None
        self.key_py = None
        self.key_crypto = None
        self.crt_crypto = None

        self.nonce_path = None
        self.id_nonce = None

        self.id_string = None
        self.ami_details = None

        self.reg_auth_methods = []
        self.reg_auth_chosen = None
        self.reg_token = None
        self.auth_data = None

        self.info_loader = InfoLoader(audit=self.audit, sysconfig=self.sysconfig)
        self.info_loader.load()
        pass

    def new_identity(self, identities=None, id_dir=consts.CONFIG_DIR, backup_dir=consts.CONFIG_DIR_OLD):
        """
        New identity - key pair for domain claim
        """
        util.make_or_verify_dir(id_dir, mode=0o755)
        util.make_or_verify_dir(backup_dir, mode=0o755)

        self.key_path = os.path.join(id_dir, consts.IDENTITY_KEY)
        self.crt_path = os.path.join(id_dir, consts.IDENTITY_CRT)
        self.nonce_path = os.path.join(id_dir, consts.IDENTITY_NONCE)
        util.delete_file_backup(self.key_path, 0o600, backup_dir=backup_dir)
        util.delete_file_backup(self.crt_path, 0o600, backup_dir=backup_dir)
        util.delete_file_backup(self.nonce_path, 0o600, backup_dir=backup_dir)

        # Generate identity nonce - random bytes
        self.id_nonce = get_random_vector(64)
        self.id_string = self.anonymize_instance_id(self.info_loader.ami_instance_id)

        # Generate new private key, 2048bit
        self.key = OpenSSL.crypto.PKey()
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        self.key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key)
        self.key_crypto = util.load_pem_private_key(self.key_pem)
        self.key_py = util.load_pem_private_key_pycrypto(self.key_pem)

        # Generate certificate
        id_to_use = identities if identities is not None else [self.id_string]
        self.crt = util.gen_ss_cert(self.key, id_to_use, validity=(25 * 365 * 24 * 60 * 60))
        self.crt_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.crt)
        self.crt_crypto = util.load_x509(self.crt_pem)

        with util.safe_open(self.crt_path, 'wb', chmod=0o600) as crt_file:
            crt_file.write(self.crt_pem)
        with util.safe_open(self.key_path, 'wb', chmod=0o600) as key_file:
            key_file.write(self.key_pem)
        with util.safe_open(self.nonce_path, 'wb', chmod=0o600) as nonce_file:
            nonce_file.write(self.id_nonce)

        return self.key, self.crt, self.key_path, self.crt_path

    def load_identity(self, id_dir=consts.CONFIG_DIR):
        """
        Loads identity from the directory
        """
        self.key_path = os.path.join(id_dir, consts.IDENTITY_KEY)
        self.crt_path = os.path.join(id_dir, consts.IDENTITY_CRT)

        if not os.path.exists(self.key_path):
            return None

        with open(self.key_path, mode='r') as key:
            self.key_pem = key.read()
            self.key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key_pem)
            self.key_crypto = util.load_pem_private_key(self.key_pem)
            self.key_py = util.load_pem_private_key_pycrypto(self.key_pem)

        with open(self.crt_path, mode='r') as crt:
            self.crt_pem = crt.read()
            self.crt = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.crt_pem)
            self.crt_crypto = util.load_x509(self.crt_pem)

        self._init_config()
        return 0

    def get_email(self):
        if self.email is not None:
            return self.email
        if self.config is not None:
            return self.config.email

    def _init_config(self):
        """
        Initializes eb_config, user_reg_type, reg_token
        :return:
        """
        if self.eb_config is None:
            self.eb_config = Core.get_default_eb_config()

        if self.user_reg_type is None:
            if self.eb_settings is not None and self.eb_settings.user_reg_type is not None:
                self.user_reg_type = self.eb_settings.user_reg_type

        if self.user_reg_type is None:
            self.user_reg_type = 'test'

        if self.reg_token is None:
            if self.eb_settings is not None and self.eb_settings.user_reg_token is not None:
                self.reg_token = self.eb_settings.user_reg_token

        if self.reg_token is None and self.eb_settings is not None and self.eb_settings.api_token is not None:
            self.reg_token = self.eb_settings.api_token

        if self.reg_token is None:
            self.reg_token = 'LSQJCHT61VTEMFQBZADO'

    def load_auth_types(self):
        """
        Requests all available authentication methods allowed for given user type
        https://api.enigmabridge.com/api/?json#get-client-authentication
        :return:
        """

        # Step 1: get possible authentication methods for the client.
        self._init_config()

        client_data_req = {
            'type': self.user_reg_type
        }

        get_auth_req = GetClientAuthRequest(client_data=client_data_req, env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=get_auth_req.__class__, data=client_data_req)

        try:
            get_auth_resp = get_auth_req.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=client_data_req,
                                     request=get_auth_req.request, response=get_auth_req.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % client_data_req)
            logger.debug('API req_full: %s' % get_auth_req.request)
            logger.debug('API res: %s' % get_auth_req.response)
            raise

        if 'authentication' not in get_auth_resp:
            raise InvalidResponse('Authentication types not present in the response')

        for m in get_auth_resp['authentication']:
            auth_m = EBRegAuth(method=m['method'], init_needed=m['init'])
            if 'initdata' in m:
                auth_m.init_data = m['initdata']
            self.reg_auth_methods.append(auth_m)

        if len(self.reg_auth_methods) == 0:
            raise InvalidResponse('No authentication methods available for this user type')

        # Step 2: choose the method
        # for now, we choose method without auth OR the first one
        no_auth_meths = [x for x in self.reg_auth_methods if not x.init_needed]
        if len(no_auth_meths) > 0:
            self.reg_auth_chosen = no_auth_meths[0]
        else:
            self.reg_auth_chosen = self.reg_auth_methods[0]

    def is_auth_needed(self):
        """
        Returns true if the selected auth method requires explicit authentication, e.g. via mail confirmation.
        :return:
        """
        if self.reg_auth_chosen is None:
            raise InvalidStatus('No registration loaded')

        return self.reg_auth_chosen.init_needed

    def is_email_required(self):
        """
        Returns true if email is required for further registration.
        This is simplified for the moment, we consider the auth with init needed as the one with email.
        :return:
        """
        return self.is_auth_needed()

    def init_auth(self):
        """
        Initializes a new registration process with the EB registration servers.
        :return:
        """
        if not self.is_auth_needed():
            return 0

        if self.config is None:
            raise ValueError('Configuration is not set')

        if self.eb_config is None:
            self.eb_config = Core.get_default_eb_config()

        client_data_req = {
            'type': self.user_reg_type,
            'method': self.reg_auth_chosen.method,
            'email': self.get_email()
        }

        init_auth_req = InitClientAuthRequest(client_data=client_data_req, env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=init_auth_req.__class__, data=client_data_req)

        try:
            init_auth_resp = init_auth_req.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=client_data_req,
                                     request=init_auth_req.request, response=init_auth_req.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % client_data_req)
            logger.debug('API req_full: %s' % init_auth_req.request)
            logger.debug('API res: %s' % init_auth_req.response)
            raise

        if 'clientid' not in init_auth_resp:
            raise InvalidResponse('Authentication initialization fails')

        self.config.client_id = init_auth_resp['clientid']
        self.config.two_stage_registration_waiting = True

        if 'authdata' in init_auth_resp:
            self.auth_data = init_auth_resp['authdata']

        return 0

    def new_registration(self):
        """
        Creates a new registration, returns new configuration object
        """
        if self.info_loader.ami_instance_id is None:
            raise EnvError('Could not extract AMI instance ID')

        if self.config is None:
            raise ValueError('Configuration is not set')

        # Step 1: create a new identity
        if self.eb_config is None:
            self.eb_config = Core.get_default_eb_config()

        # Ami details anonymization
        self.ami_details = self.info_loader.ami_results
        self.ami_details[InfoLoader.AMI_KEY_INSTANCE_ID] = self.id_string

        client_data_reg = {
            'name': self.id_string,
            'authentication': 'type',
            'type': self.user_reg_type,
            'token': self.reg_token,
            'ami': self.ami_details,
            'email': self.get_email()
        }

        clid = self.config.client_id
        if clid is not None and len(clid) > 0:
            client_data_reg['clientid'] = clid

        regreq = RegistrationRequest(client_data=client_data_reg, env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=regreq.__class__, data=client_data_reg)

        try:
            regresponse = regreq.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=client_data_reg,
                                     request=regreq.request, response=regreq.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % client_data_reg)
            logger.debug('API req_full: %s' % regreq.request)
            logger.debug('API res: %s' % regreq.response)
            raise

        if 'username' not in regresponse:
            raise InvalidResponse('Username was not present in the response')

        # Step 2: ask for API key
        client_api_req = {
            'authentication': 'password',
            'username': regresponse['username'],
            'password': regresponse['password']
        }

        endpoint = {
            "ipv4": "123.23.23.23",
            "ipv6": "fe80::2e0:4cff:fe68:bcc2/64",
            "country": "gb",
            "network": "plusnet",
            "location": [0.34, 10]
        }

        apireq = ApiKeyRequest(client_data=client_api_req, endpoint=endpoint,
                               env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=apireq.__class__, data=client_api_req)

        try:
            apiresponse = apireq.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=client_api_req, request=apireq.request, response=apireq.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % client_api_req)
            logger.debug('API req_full: %s' % apireq.request)
            logger.debug('API res: %s' % apireq.response)
            raise

        if 'apikey' not in apiresponse:
            raise InvalidResponse('ApiKey was not present in the getApiKey response')

        # Step 3: save new identity configuration
        self.config.email = self.get_email()
        self.config.username = regresponse['username']
        self.config.password = regresponse['password']
        self.config.apikey = apiresponse['apikey']
        self.config.servers = apiresponse['servers']
        self.config.generated_time = (datetime.utcnow() - datetime(1970, 1, 1)).total_seconds()
        self.config.two_stage_registration_waiting = False
        return self.config

    def new_domain(self):
        """
        Enrols for a new AWS domain
        :return:
        """
        api_data_reg = {
            'username': self.config.username,
            'apikey': self.config.apikey,
            'certificate': self.get_cert_pem_json()
        }

        req = EnrolDomainRequest(api_data=api_data_reg, env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=req.__class__, data=api_data_reg)

        try:
            resp = req.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=api_data_reg, request=req.request, response=req.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % api_data_reg)
            logger.debug('API req_full: %s' % req.request)
            logger.debug('API res: %s' % req.response)
            raise

        if resp is None:
            raise InvalidResponse('Response is invalid')

        if 'domain' not in resp:
            raise InvalidResponse('Domain was not present in the response')

        # Step 3: save new identity configuration
        self.config.nsdomain = resp['domain']
        return self.config

    def refresh_domain(self, ip_to_use=None, dns_data=None):
        """
        Attempts to refresh previously assigned domain after AWS restart
        Modifies self.config with returned domains
        :return:
        """
        resp_update = self.refresh_domain_call(ip_to_use=ip_to_use, dns_data=dns_data)

        # Sort the domains by the key (length, lexicographic)
        domains = resp_update['domains']
        domains.sort()
        domains.sort(key=len, reverse=True)

        self.config.domains = domains
        self.config.last_ipv4 = self.info_loader.ami_public_ip
        self.config.last_ipv4_private = self.info_loader.ami_local_ip
        return self.config

    def refresh_domain_call(self, ip_to_use=None, dns_data=None):
        """
        Basic DNS call - request for a new DNS name allocation or the refresh.
        :return: resp_update from the UpdateDomainRequest
        """

        # In case of the private network, public address is not usable.
        if ip_to_use is None:
            if self.config.is_private_network:
                ip_to_use = self.info_loader.ami_local_ip
            else:
                ip_to_use = self.info_loader.ami_public_ip

        # Request config.
        api_data_req_body = {
            'ipv4': ip_to_use,
            'username': self.config.username,
            'apikey': self.config.apikey
        }

        req = GetDomainChallengeRequest(api_data=api_data_req_body, env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=req.__class__, data=api_data_req_body)

        try:
            resp = req.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=api_data_req_body, request=req.request, response=req.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % api_data_req_body)
            logger.debug('API req_full: %s' % req.request)
            logger.debug('API res: %s' % req.response)
            raise

        if 'authentication' not in resp:
            raise InvalidResponse('Authentication not present in the response')

        auth_type = resp['authentication']
        if auth_type not in ['signature', 'challenge']:
            raise InvalidResponse('Unsupported authentication type ' + auth_type)

        # Step 2 - claim the domain
        challenge_response = resp['challenge']
        api_data_req = {
            'username': self.config.username,
            'apikey': self.config.apikey,
            'authentication': auth_type,
            'response': challenge_response
        }

        if dns_data is not None:
            api_data_req['dnsdata'] = dns_data

        payload = base64.b64encode(json.dumps(api_data_req))
        signer = self.key_crypto.signer(padding=padding.PKCS1v15(), algorithm=hashes.SHA256())
        signer.update(payload)
        signature = base64.b64encode(signer.finalize())

        signature_aux = {
            'signature': {
                'payload': payload,
                'value': signature
            },
        }

        req_upd = UpdateDomainRequest(api_data=api_data_req, env=self.config.env, config=self.eb_config)
        req_upd.aux_data = signature_aux
        self.audit.audit_request(req_type=req_upd.__class__, data=api_data_req)

        try:
            resp_update = req_upd.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=api_data_req, request=req_upd.request,
                                     response=req_upd.response, signature_aux=signature_aux,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % api_data_req)
            logger.debug('Signature: %s' % signature_aux)
            logger.debug('API req_full: %s' % req.request)
            logger.debug('API res: %s' % req.response)
            raise

        if 'domains' not in resp_update:
            raise InvalidResponse('domains not in the response')
        return resp_update

    def install_status(self, status):
        """
        Uploads install status to the EB server.
        :return:
        """
        # Request config.
        api_data_req_body = {
            'username': self.config.username,
            'apikey': self.config.apikey
        }

        req = InstallStatusRequest(api_data=api_data_req_body, status_data=status,
                                   env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=req.__class__, data=api_data_req_body)

        try:
            resp = req.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=api_data_req_body, request=req.request, response=req.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % api_data_req_body)
            logger.debug('API req_full: %s' % req.request)
            logger.debug('API res: %s' % req.response)
            raise

        return resp

    def send_audit_logs(self, preimage, log):
        """
        Sends audit log file to the EB server for debugging
        :param preimage:
        :param log:
        :return:
        """
        api_data_req_body = {
            'username': self.config.username if self.config is not None else None,
            'apikey': self.config.apikey if self.config is not None else None
        }

        if api_data_req_body['apikey'] is None:
            api_data_req_body = None

        effort = {
            'preimage': preimage,
            'secondpreimage': util.sha1(preimage, as_hex=True),
            'collision': 20
        }

        req = SendLogRequest(api_data=api_data_req_body, effort=effort, log=log,
                             env=self.config.env, config=self.eb_config)
        self.audit.audit_request(req_type=req.__class__, data=api_data_req_body)

        try:
            resp = req.call()
        except Exception as e:
            self.audit.audit_exception(e)
            self.audit.audit_request(api_data=api_data_req_body, effort=effort, response=req.response,
                                     env=self.config.env, config=self.eb_config)
            logger.debug('API req: %s' % api_data_req_body)
            logger.debug('API req_effort: %s' % effort)
            logger.debug('API res: %s' % req.response)
            raise

        return resp

    def txt_le_validation_dns_data(self, domain_token_list):
        """
        Generates DNS data for LetsEncrypt DNS TXT domain validation
        for the given list of (domain, TXT) record pair list.
        :rtype : object
        :param domain_token_list:
        :return:
        """
        if not isinstance(domain_token_list, types.ListType):
            domain_token_list = [domain_token_list]

        dns_data = []
        for pair in domain_token_list:
            if not isinstance(pair, types.TupleType):
                raise ValueError('txt_le_validation_dns_data expects a pair or list of pairs')

            domain, txt = pair[0], pair[1]
            cur = {
                'type': 'TXT',
                'name': '_acme-challenge',
                'value': txt,
            }

            if domain is not None:
                cur['domain'] = domain

            dns_data.append(cur)

        return dns_data

    def get_cert_pem_json(self):
        """
        Extracts simple base64 encoded certificate (no newlines, ASCII armor) from the self.crt_pem in PEM format.
        :return:
        """
        result = ''
        for line in self.crt_pem.split('\n'):
            line = line.strip()
            if line.startswith('---'):
                continue
            result += line
        return result

    def anonymize_instance_id(self, instance_id):
        """
        Anonymizes instance ID by HMACing it with the client secret
        :param instance_id:
        :return:
        """
        return self.anonymize_param('instance-id', instance_id)

    def anonymize_param(self, param_name, param_value):
        """
        Anonymizes a parameter by HMACing it with the client secret
        :param param_name:
        :param param_value:
        :return:
        """
        m = util.hmac_obj(self.id_nonce, 'paramhash;')
        m.update(param_name)
        m.update(';')
        m.update(param_value)
        digest = m.digest()
        return base64.b16encode(digest)



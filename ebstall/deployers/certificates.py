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

from ebstall.consts import PROVISIONING_SERVERS, LE_VERIFY_DNS
from ebstall.deployers import letsencrypt

__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


class Certificates(object):
    """
    Handles LetsEncrypt certificate lifecycle
    """
    def __init__(self, sysconfig=None, audit=None, config=None, reg_svc=None, staging=None, cmdargs=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.audit = audit
        self.config = config
        self.reg_svc = reg_svc

        self.staging = None
        self.cmdargs = None
        self.lets_encrypt = None
        self.hostname = None
        self.domains = None
        self.subdomains = []

    def is_staging(self):
        """
        Returns true if staging
        :return: 
        """
        if self.staging is not None:
            return self.staging
        if self.cmdargs is not None:
            return self.cmdargs.le_staging
        return False

    def set_domains(self, domains, primary=None, set_hostname=True):
        """
        Sets the main assigned domains.
        :param domains:
        :param primary:
        :param set_hostname:
        :return:
        """
        if domains is None or len(domains) == 0:
            domains = ['localhost']

        if not isinstance(domains, types.ListType):
            domains = [domains]

        # sort by (length, lexicographic)
        domains.sort()
        domains.sort(key=len, reverse=True)

        # if primary domain was not set use the longest one (convention).
        if primary is not None:
            if primary not in domains:
                domains.insert(0, primary)
            elif primary != domains[0]:
                raise ValueError('Primary domain has to be listed first in the domain list')
        else:
            primary = domains[0]

        self.domains = domains
        if set_hostname:
            self.set_hostname(primary)

    def set_subdomains(self, subdomains):
        """
        Sets the subdomains
        :param subdomains: 
        :return: 
        """
        if self.subdomains is None:
            self.subdomains = []
        if subdomains is None:
            return
        if not isinstance(subdomains, types.ListType):
            subdomains = [subdomains]
        self.subdomains = sorted(list(set(list(subdomains))))

    def add_subdomains(self, subdomains):
        """
        Add subdomain to the list        
        :param subdomains: 
        :return: 
        """
        if self.subdomains is None:
            self.subdomains = []
        if subdomains is None:
            return
        if not isinstance(subdomains, types.ListType):
            subdomains = [subdomains]

        self.subdomains += subdomains
        self.subdomains = sorted(list(set(list(subdomains))))

    def check_hostname_domains_consistency(self):
        """
        Checks if hostname is on the domains list
        :return: 
        """
        return self.domains is not None \
                and isinstance(self.domains, types.ListType) \
                and self.hostname == self.domains[0]

    def set_hostname(self, hostname):
        """
        Set main primary hostname.
        Should not be called outside the module (by user), use set_domains instead.
        :return:
        """
        if hostname is None:
            hostname = 'localhost'

        self.hostname = hostname
        self.config.hostname = hostname
        if not self.check_hostname_domains_consistency():
            raise ValueError('Hostname is not consistent with domains, please, rather use set_domains()')

    def load_domains_config(self):
        """
        Loads domains from the config
        :return: 
        """
        self.set_domains(self.config.domains)
        self.set_subdomains(self.config.subdomains)

    def get_domain_certificate_set(self):
        """
        Returns arrays of domains + subdomains that should be in the single certificate.
        By default there is only one certificate set.
        :return: 
        """
        if self.domains is None:
            logger.debug('Loading domains from the configuration')
            self.load_domains_config()

        return [list(self.domains + self.subdomains)]

    #
    # Domain registration
    #

    def register_subdomains(self):
        """
        Register subdomains in provider
        :return: 
        """
        if self.subdomains is None or len(self.subdomains) == 0:
            logger.debug('Subdomain registration skipped - no subdomains')
            return
        logger.debug('Going to register subdomains: %s' % (', '.join(self.subdomains)))
        self.reg_svc.register_subdomains(self.subdomains)

    #
    # LE Enroll & Renew
    #

    def _init_le(self, new=False, cert_set=None, no_domains=False, local_only=False):
        """
        Initializes LE instance
        :param cert_set: 
        :param no_domains: 
        :param local_only: 
        :return: 
        """
        if self.lets_encrypt is not None and not new and not local_only:
            return

        if cert_set is None and not no_domains:
            cert_sets = self.get_domain_certificate_set()
            if len(cert_sets) != 1:
                raise errors.Error('Invalid certificate domain set size. Currently supported only one.')
            cert_set = cert_sets[0]

        lets_encrypt = letsencrypt.LetsEncrypt(email=self.config.email, domains=cert_set,
                                               staging=self.is_staging(),
                                               audit=self.audit, sysconfig=self.sysconfig)
        if not local_only:
            self.lets_encrypt = lets_encrypt
        return lets_encrypt

    def le_dns(self, domain=None, token=None, mdns=None, p=None, done=None, abort=None, *args, **kwargs):
        """
        DNS challenge solver for LE DNS verification
        :param domain:
        :param token:
        :param mdns:
        :param p:
        :param abort:
        :param args:
        :param kwargs:
        :return:
        """
        if domain is None or token is None:
            raise ValueError('Domain or token is none')
        if done is None:
            raise ValueError('Cannot signalize done - its None')

        # Prepare DNS TXT data for LE
        domain_parts = domain.split('.', 1)
        dns_data = self.reg_svc.txt_le_validation_dns_data((domain_parts[1], token))

        # Update domain DNS settings
        self.reg_svc.refresh_domain_call(dns_data=dns_data)

        # Call done callback
        done()

    def get_le_method(self, le_method=None):
        """
        Decides which method to use.
        :param le_method:
        :return:
        """
        return self.config.get_le_method(le_method=le_method)

    def renew_needed(self):
        """
        Returns true if renew should be performed
        :return: 
        """
        self._init_le()
        return self.lets_encrypt.test_certificate_for_renew(domain=self.hostname,
                                                            renewal_before=60 * 60 * 24 * 20) != 0

    def get_cert_dir(self):
        """
        Returns certificate directory for the main certificate
        :return: 
        """
        self._init_le()
        return self.lets_encrypt.get_certificate_dir(self.hostname)

    def le_enroll(self, le_method=None):
        """
        Enrolls to LetsEncrypt with specified domains
        :param le_method:
        :return:
        """

        # If hostname is none/localhost, there is no point for lets encrypt here. Maybe later.
        if self.hostname is None or self.hostname == 'localhost':
            logger.info("Hostname is none/localhost, no letsencrypt operation will be performed")
            return 1

        cert_sets = self.get_domain_certificate_set()
        if len(cert_sets) != 1:
            raise errors.Error('Invalid certificate domain set size. Currently supported only one.')

        self.lets_encrypt = letsencrypt.LetsEncrypt(email=self.config.email, domains=cert_sets[0],
                                                    staging=self.is_staging(),
                                                    audit=self.audit, sysconfig=self.sysconfig)

        le_method = self.get_le_method(le_method=le_method)

        # noinspection PyUnusedLocal
        ret, out, err = -1, None, None
        if le_method == LE_VERIFY_DNS:
            logger.debug('Using DNS validation')
            mdns = self.lets_encrypt.manual_dns(expand=True, on_domain_challenge=self.le_dns)
            ret, out, err = mdns.start()

        else:
            ret, out, err = self.lets_encrypt.certonly()

        if ret != 0:
            raise errors.SetupError('Certificate could not be created, return code: %s' % ret)

        return 0

    def le_renew(self, le_method=None):
        """
        Renews LetsEncrypt certificate.
        :return: 0 if certificate was renewed 1 if OK but no renewal was needed, error otherwise
        """
        cert_sets = self.get_domain_certificate_set()
        if len(cert_sets) != 1:
            raise errors.Error('Invalid certificate domain set size. Currently supported only one.')

        self.lets_encrypt = letsencrypt.LetsEncrypt(email=self.config.email, domains=cert_sets[0],
                                                    staging=self.is_staging(),
                                                    audit=self.audit, sysconfig=self.sysconfig)

        if self.lets_encrypt.is_certificate_ready(domain=self.hostname) != 0:
            logger.info('Certificate does not exist, could not renew')
            return 2

        priv_file, cert_file, ca_file = self.lets_encrypt.get_cert_paths(domain=self.hostname)
        cert_time_before = util.get_file_mtime(cert_file)

        # Call letsencrypt renewal
        le_method = self.get_le_method(le_method=le_method)

        # noinspection PyUnusedLocal
        ret, out, err = -1, None, None
        if le_method == LE_VERIFY_DNS:
            logger.debug('Using DNS validation')
            mdns = self.lets_encrypt.manual_dns(expand=True, on_domain_challenge=self.le_dns)
            ret, out, err = mdns.start()
        else:
            ret, out, err = self.lets_encrypt.renew()

        if ret != 0:
            logger.info('LE renewal failed with code: %s' % ret)
            return 3

        return 0


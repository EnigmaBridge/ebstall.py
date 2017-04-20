#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import time
import traceback

import coloredlogs

from ebstall.deployers import dnsmasq
from ebstall.deployers import nginx
from ebstall.deployers import openvpn
from ebstall.deployers import php
from ebstall.deployers import supervisord
from ebstall.deployers import vpnauth
from ebstall.deployers import pspace_web

import errors
import util
from cli import Installer
from core import Core

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.ERROR)


class VpnInstaller(Installer):
    """
    Extended installer - with VPN.
    """

    def __init__(self, *args, **kwargs):
        """
        Init core
        :param args:
        :param kwargs:
        :return:
        """
        Installer.__init__(self, *args, **kwargs)
        self.ovpn = None
        self.dnsmasq = None
        self.nginx = None
        self.supervisord = None
        self.vpnauth = None
        self.php = None
        self.pspace_web = None

        self.vpn_keys = None, None, None
        self.vpn_crl = None
        self.vpn_client_config = None

    def init_argparse(self):
        """
        Adding new VPN related arguments
        :return:
        """
        parser = Installer.init_argparse(self)
        return parser

    def is_email_required(self):
        """
        Returns true if the given scenario requires user email
        :return:
        """
        return True

    def ask_for_email_reason(self, is_required=None):
        """
        Reason why we need email - required in VPN case.
        :param is_required:
        :return:
        """
        self.tprint('We need your email address for:\n'
                    '   a) identity verification for EnigmaBridge account \n'
                    '   b) LetsEncrypt certificate registration\n'
                    '   c) PKI setup - VPN configuration')
        self.tprint('We will send you a verification email.')
        self.tprint('Without a valid e-mail address you won\'t be able to continue with the installation\n')

    def init_install_intro_text(self):
        """
        Shows installation intro text when installation starts.
        :return:
        """
        self.tprint('Going to install Private Space backed by Enigma Bridge FIPS140-2 encryption service.\n')

    def get_args_intro(self, parser):
        """
        Argument parser intro text
        :return:
        """
        parser.description = 'EnigmaBridge Private Space installer'

    def update_intro(self):
        """
        Updates intro text for CLI header - adds version to it.
        :return:
        """
        self.intro = '-'*self.get_term_width() + \
                     ('\n    Enigma Bridge Installer command line interface (v%s) \n' % self.version) + \
                     '\n    usage - shows simple command list' + \
                     '\n    init  - initializes the Private Space\n'

        if self.first_run:
            self.intro += '            run this when running for the first time\n'

        self.intro += '\n    More info: https://enigmabridge.com/amazonpki \n' + \
                      '-'*self.get_term_width()

    def do_test_vpn_ports(self, line):
        """Tests if VPN server ports are accessible"""
        public_ip = self.cfg_get_raw_ip()
        port = 1194
        tcp = False

        self.tprint('Testing IP: %s, ports %s' % (public_ip, port))
        res_value = util.test_port_routable(host=public_ip, port=port, tcp=tcp, with_server=True)
        if res_value is None:
            self.tprint('Server seems to be running, UDP scan cannot be performed')
            return

        self.tprint('Port %s, echo server, reachable: %s' % (port, res_value))

    def do_update_ejbca_install(self, line):
        """Updates EJBCA distribution from the provisioning server"""
        self.load_base_settings()
        self.init_load_settings()
        self.init_services()
        self.init_services()
        self.ejbca.update_installation()

    def init_test_ports_pre_install_res(self, host=None, *args, **kwargs):
        failed_ports = Installer.init_test_ports_pre_install_res(self, host, *args, **kwargs)

        vpn_ok = util.test_port_routable(host=host, port=openvpn.OpenVpn.PORT_NUM, tcp=openvpn.OpenVpn.PORT_TCP,
                                         with_server=True, audit=self.audit)
        if not vpn_ok:
            failed_ports.append(util.Port(port=openvpn.OpenVpn.PORT_NUM, tcp=openvpn.OpenVpn.PORT_TCP,
                                          service='OpenVPN'))
        return failed_ports

    def init_print_intro(self):
        """
        Prints introduction text before the installation.
        :return:
        """
        self.tprint('')
        self.cli_separator()
        self.tprint('\nThe installation is about to start.')
        self.tprint('During the installation we collect the following ec2 metadata for enrolment to '
                    'Enigma Bridge CloudHSM: ')
        self.tprint('  - ami-id')
        self.tprint('  - instance-id (anonymized, HMAC)')
        self.tprint('  - instance-type')
        self.tprint('  - placement (AWS region)')
        self.tprint('  - local-ipv4')
        self.tprint('  - public-ipv4')
        self.tprint('  - public-hostname')
        self.tprint('')
        self.tprint(self.wrap_term(single_string=True, max_width=80,
                                   text='We will send the data above with your e-mail address (if entered) '
                                        'to our EnigmaBridge registration server during this initialization. '
                                        'We will use it to:'))
        self.tprint('  - generate a dynamic DNS name (e.g., cambridge1.umph.io);')
        self.tprint('  - create a client account at the Enigma Bridge CloudHSM service.')
        self.tprint('')
        self.tprint(self.wrap_term(single_string=True, max_width=80,
                                   text='The Enigma Bridge account allows you access to secure hardware, which is used '
                                        'to generate new RSA keys and use them securely to sign certificates, CRLs, '
                                        'and OCSP responses.'))
        self.tprint('')
        text = 'The static DNS name allows you securely access the PKI web interface as ' \
               'it will have a valid browser-trusted HTTPS certificate as soon as this ' \
               'initialization is completed. No more manual over-ride of untrusted ' \
               'certificates and security exceptions in your browser. ' \
               'We need to communicate with a public certification authority LetsEncrypt. ' \
               'LetsEncrypt will verify a certificate request is genuine either by connecting ' \
               'to port 443 on this instance or by a DNS challenge on the domain ' \
               'if 443 is blocked.'

        self.tprint(self.wrap_term(single_string=True, max_width=80, text=text))
        self.tprint('')
        self.tprint(self.wrap_term(single_string=True, max_width=80,
                             text='More details and our privacy policy can be found at: '
                                  'https://enigmabridge.com/amazonpki'))
        self.tprint('')
        self.tprint('Please make sure the following ports are reachable: ')
        self.tprint('  tcp: 443, 8442, 8443, udp: 1194')

        self.tprint('')
        text = 'In order to continue with the installation we need your consent with the network ' \
               'communication the instance will be doing during the installation as outlined in' \
               'the description above'
        self.tprint(self.wrap_term(single_string=True, max_width=80,text=text))

        self.tprint('')

    def init_show_p12_info(self, new_p12, new_config):
        """
        Informs user where to get P12 file to log into EJBCA admin panel.
        :return:
        """
        if new_p12 is None:
            raise ValueError('P12 file is not defined')

        if new_config is None:
            new_config = self.config

        self.tprint('')
        self.tprint(self.t.underline('Please setup your computer to manage users of your Private Space'))
        time.sleep(0.5)

        public_hostname = self.ejbca.hostname if self.domain_is_ok else self.cfg_get_raw_hostname()
        self.tprint('\nDownload your administration key: %s' % new_p12)
        self.tprint('  scp -i <your_Amazon_PEM_key> ec2-user@%s:%s .' % (public_hostname, new_p12))
        self.tprint_sensitive('  Password protecting the key is: %s' % self.ejbca.superadmin_pass)
        self.tprint('\nPlease use the following page for a detailed guide how to import the key file '
                    '(aka, P12 file): https://enigmabridge.com/support/aws13076')
        self.tprint('\nOnce you download the key file AND import it to your computer browser/keychain you can '
                    'connect to the PKI/VPN admin interface:')

        if self.domain_is_ok:
            for domain in new_config.domains:
                self.tprint('  https://%s:%d' % (domain, self.ejbca.PORT_PUBLIC))
        else:
            self.tprint('  https://%s:%d' % (self.cfg_get_raw_hostname(), self.ejbca.PORT_PUBLIC))

        self.tprint('')
        txt = self.t.green('IMPORTANT') +\
              ': We recommend using the "Private Space" to download your administrator key and an ' \
              'email with instructions will be delivered instantly (please check your spam/junk folder if' \
              ' you can\'t find it). Using instructions above increases flexibility for management ' \
              'but it also assumes expert knowledge and ability to foresee impact of your actions.'

        self.tprint(self.wrap_term(single_string=True, max_width=80, text=txt))

        self.tprint('\n\nPlease contact us at support@enigmabridge.com or '
                    'https://enigmabridge.freshdesk.com/helpdesk/tickets/new if you need assistance.')

    def init_main_try(self):
        """
        Main installer block, called from the global try:
        :return:
        """
        self.init_config_new_install()
        self.init_services()
        self.ovpn = openvpn.OpenVpn(sysconfig=self.syscfg, audit=self.audit, write_dots=True)
        self.dnsmasq = dnsmasq.DnsMasq(sysconfig=self.syscfg, audit=self.audit, write_dots=True)
        self.nginx = nginx.Nginx(sysconfig=self.syscfg, audit=self.audit, write_dots=True)
        self.supervisord = supervisord.Supervisord(sysconfig=self.syscfg, audit=self.audit, write_dots=True)
        self.vpnauth = vpnauth.VpnAuth(sysconfig=self.syscfg, audit=self.audit, write_dots=True,
                                       supervisord=self.supervisord, mysql=self.mysql, ovpn=self.ovpn)
        self.php = php.Php(sysconfig=self.syscfg, audit=self.audit, write_dots=True)
        self.pspace_web = pspace_web.PrivSpaceWeb(sysconfig=self.syscfg, audit=self.audit, write_dots=True,
                                                  mysql=self.mysql, nginx=self.nginx, config=self.config)

        self.ejbca.do_vpn = True
        self.ejbca.openvpn = self.ovpn

        # Get registration options and choose one - network call.
        self.reg_svc.load_auth_types()

        # Show email prompt and intro text only for new initializations.
        res = self.init_prompt_user()
        if res != 0:
            return self.return_code(res)

        # If VPN server was running, stop it now - easier port testing, minimal interference.
        self.ovpn.switch(stop=True)
        self.dnsmasq.switch(stop=True)
        self.nginx.switch(stop=True)

        # Disable services which may interfere installation.
        self.init_prepare_install()

        # System check proceeds (mem, network).
        # We do this even if we continue with previous registration, to have fresh view on the system.
        # Check if we have EJBCA resources on the drive
        res = self.init_test_environment()
        if res != 0:
            return self.return_code(res)

        # Determine if we have enough RAM for the work.
        # If not, a new swap file is created so the system has at least 2GB total memory space
        # for compilation & deployment.
        self.syscfg.install_epiper()
        res = self.install_check_memory(syscfg=self.syscfg)
        if res != 0:
            return self.return_code(res)

        # Update the OS.
        if not self.args.no_os_update:
            self.update_main_try()

        # Preferred LE method? If set...
        self.last_is_vpc = False

        # Lets encrypt reachability test, if preferred method is DNS - do only one attempt.
        # We test this to detect VPC also. If 443 is reachable, we are not in VPC
        res, args_le_preferred_method = self.init_le_vpc_check(self.get_args_le_verification(),
                                                               self.get_args_vpc(), reg_svc=self.reg_svc)
        if res != 0:
            return self.return_code(res)

        # Firewall tuning
        self.ejbca.setup_os()
        self.ovpn.setup_os()

        # Test ports opened here...
        res = self.init_test_ports_pre_install()
        if res != 0:
            return self.return_code(res)

        # User registration may be multi-step process.
        res, new_config = self.init_enigma_registration()
        if res != 0:
            return self.return_code(res)

        # Custom hostname for EJBCA - not yet supported
        new_config.ejbca_hostname_custom = False
        new_config.is_private_network = self.last_is_vpc
        new_config.le_preferred_verification = args_le_preferred_method

        # Assign a new dynamic domain for the host
        res, self.domain_is_ok = self.init_domains_check(reg_svc=self.reg_svc)
        new_config = self.reg_svc.config
        if res != 0:
            return self.return_code(res)

        # Dump config
        conf_file = Core.write_configuration(new_config)
        self.tprint('New configuration was written to: %s\n' % conf_file)

        # Certbot
        res = self.init_certbot()
        if res != 0:
            return self.return_code(res)

        # Database
        res = self.init_database()
        if res != 0:
            return self.return_code(res)

        # SoftHSMv1 reconfigure
        res = self.init_softhsm(new_config=new_config)
        if res != 0:
            return self.return_code(res)

        # EJBCA configuration
        res = self.init_install_ejbca(new_config=new_config)
        if res != 0:
            return self.return_code(res)

        # Generate new keys
        res = self.init_create_vpn_eb_keys()
        if res != 0:
            return self.return_code(res)

        # JBoss restart is needed - so it sees the new keys
        self.init_jboss_restart()

        # VPN setup - create CA, profiles, server keys, CRL
        self.init_ejbca_vpn()

        # LetsEncrypt enrollment
        res = self.init_le_install()
        if res != 0:
            return self.return_code(res)

        # VPN server - install, configure, enable, start
        self.tprint('\n\nInstalling & configuring VPN server')
        self.init_vpn()
        self.init_supervisord()
        self.init_dnsmasq()
        self.init_nginx()
        self.init_vpnauth()
        self.init_privatespace_web()

        self.init_nginx_start()
        self.init_vpn_start()

        self.tprint('')
        self.init_celebrate()
        self.cli_sleep(3)
        self.cli_separator()

        # Finalize, P12 file & final instructions
        new_p12 = self.ejbca.copy_p12_file()
        self.init_show_p12_info(new_p12=new_p12, new_config=new_config)

        # Generate VPN client for the admin. openvpn link will be emailed
        self.init_create_vpn_users()

        # Install to the OS - cron job & on boot service
        res = self.init_install_os_hooks()
        if res != 0:
            return self.return_code(res)

        # Test if main admin port of EJBCA is reachable - server is running. Public port needed for VPN config download
        self.init_test_ejbca_ports_reachability(check_public=True)

        self.cli_sleep(5)
        return self.return_code(0)

    def init_jboss_restart(self):
        """
        Restarts jboss
        :return: 
        """
        if self.args.no_ejbca_install:
            logger.warning('EJBCA disabled, JBoss restart skipped')
            return
        self.ejbca.jboss_restart()

    def init_ejbca_vpn(self):
        """
        Configures EJBCA for use for VPN
        Throws an exception if something goes wrong.
        :return:
        """
        if self.args.no_ejbca_install:
            logger.warning('EJBCA disabled, cannot prepare VPN vars')
            return

        ret = self.ejbca.vpn_create_ca()
        if ret != 0:
            raise errors.SetupError('Cannot create CA for the VPN')

        ret = self.ejbca.vpn_create_profiles()
        if ret != 0:
            raise errors.SetupError('Cannot create new identity profiles in EJBCA for VPN')

        time.sleep(2)
        ret = self.ejbca.vpn_create_server_certs()
        if ret != 0:
            raise errors.SetupError('Cannot create new certificate for VPN server')

        ret = self.ejbca.vpn_create_crl()
        if ret != 0:
            raise errors.SetupError('Cannot generate new CRL for the VPN')

        self.vpn_keys = self.ejbca.vpn_get_server_cert_paths()
        self.vpn_crl = self.ejbca.vpn_get_crl_path()
        self.vpn_client_config = self.ejbca.vpn_get_vpn_client_config_path()
        self.ejbca.vpn_install_cron()

    def init_vpn(self):
        """
        Installs and configures VPN daemon.
        Throws an exception if something goes wrong.
        :return:
        """
        self.ovpn.config = self.config

        ret = self.ovpn.install()
        if ret != 0:
            raise errors.SetupError('Cannot install openvpn package')

        ret = self.ovpn.generate_dh_group()
        if ret != 0:
            raise errors.SetupError('Cannot generate a new DH group for VPN server')

        self.ovpn.configure_server()

        vpn_ca, vpn_cert, vpn_key = self.vpn_keys
        if self.args.no_ejbca_install:
            logger.warning('EJBCA disabled, VPN wont be configured properly')

        else:
            ret = self.ovpn.store_server_cert(ca=vpn_ca, cert=vpn_cert, key=vpn_key)
            if ret != 0:
                raise errors.SetupError('Cannot install VPN certificate+key to the VPN server')

            self.ovpn.configure_crl(crl_path=self.vpn_crl)

        # Configure VPN client configuration file to match the server config
        self.ovpn.client_config_path = self.vpn_client_config
        self.ovpn.configure_client()
        self.ejbca.jboss_fix_privileges()

        # OS configuration
        ret = self.ovpn.setup_os()
        if ret != 0:
            raise errors.SetupError('Cannot configure OS for the openvpn server (ip forwarding, masquerade)')

        # Starting VPN server
        ret = self.ovpn.enable()
        if ret != 0:
            raise errors.SetupError('Cannot set openvpn server to start after boot')

        Core.write_configuration(self.config)

    def init_vpn_start(self):
        """
        Starts VPN server
        :return:
        """
        if self.args.no_ejbca_install:
            logger.warning('EJBCA disabled, VPN wont be started')
            return

        ret = self.ovpn.switch(restart=True)
        if ret != 0:
            raise errors.SetupError('Cannot start openvpn server')

    def init_dnsmasq(self):
        """
        Initializes DNSMasq
        Throws an exception if something goes wrong.
        :return:
        """
        self.dnsmasq.hostname = self.ejbca.hostname
        self.dnsmasq.vpn_server_ip = self.ovpn.get_ip_vpn_server()

        ret = self.dnsmasq.install()
        if ret != 0:
            raise errors.SetupError('Error with dnsmasq installation')

        self.dnsmasq.configure_server()

        ret = self.dnsmasq.enable()
        if ret != 0:
            raise errors.SetupError('Error with setting dnsmasq to start after boot')

        ret = self.dnsmasq.switch(restart=True)
        if ret != 0:
            raise errors.SetupError('Error in starting dnsmasq daemon')

    def init_nginx(self):
        """
        Initializes Nginx
        Throws an exception if something goes wrong.
        :return:
        """
        self.nginx.hostname = self.ejbca.hostname
        self.nginx.domains = self.config.domains
        self.nginx.internal_addresses = ['%s/%s' % (self.ovpn.get_ip_net(), self.ovpn.get_ip_net_size())]
        self.nginx.cert_dir = self.ejbca.cert_dir
        self.nginx.html_root = self.pspace_web.get_public_dir()  # Laravel based private space landing page

        ret = self.nginx.install()
        if ret != 0:
            raise errors.SetupError('Error with nginx installation')

        # Loading basic info
        self.nginx.load_configuration()

        # Install PHP
        self.init_php()

        # Configure properly
        self.nginx.configure_server()

        # Use Nginx certbot plugin for renewal
        self.config.le_renew_nginx = True
        Core.write_configuration(self.config)

        ret = self.nginx.enable()
        if ret != 0:
            raise errors.SetupError('Error with setting nginx to start after boot')

    def init_nginx_start(self):
        """
        Starts Nginx
        Can start it after it is properly configured & PHP is installed
        :return: 
        """
        ret = self.nginx.switch(restart=True)
        if ret != 0:
            raise errors.SetupError('Error in starting nginx daemon')

    def init_php(self):
        """
        Installs php
        :return: 
        """
        self.php.user = self.nginx.nginx_user
        self.php.install()
        self.php.configure()

        ret = self.php.enable()
        if ret != 0:
            raise errors.SetupError('Error with setting php to start after boot')

        ret = self.php.switch(restart=True)
        if ret != 0:
            raise errors.SetupError('Error in starting php daemon')

    def init_privatespace_web(self):
        """
        Initializes private space web
        :return: 
        """
        self.pspace_web.config = self.config
        self.pspace_web.user = self.nginx.nginx_user
        self.pspace_web.stats_file_path = self.vpnauth.get_stats_file_path()
        self.pspace_web.admin_email = self.config.email
        self.pspace_web.hostname = self.ejbca.hostname
        self.pspace_web.vpn_net_addr = self.ovpn.get_ip_net()
        self.pspace_web.vpn_net_size = self.ovpn.get_ip_net_size()
        self.pspace_web.vpn_net_server = self.ovpn.get_ip_vpn_server()

        self.pspace_web.install()
        self.pspace_web.configure()
        Core.write_configuration(self.config)

    def init_supervisord(self):
        """
        Installs supervisord
        :return:
        """
        self.supervisord.install()

        ret = self.supervisord.enable()
        if ret != 0:
            raise errors.SetupError('Error with setting supervisord to start after boot')

        ret = self.supervisord.switch(restart=True)
        if ret != 0:
            raise errors.SetupError('Error in starting supervisord daemon')

    def init_vpnauth(self):
        """
        Installs vpn auth server
        Has to be called after VPN is installed buf before VPN is started
        :return:
        """
        self.vpnauth.config = self.config
        self.vpnauth.ejbca = self.ejbca

        self.vpnauth.install()
        self.vpnauth.configure()
        self.vpnauth.configure_vpn_server()
        Core.write_configuration(self.config)

        self.vpnauth.enable()
        self.vpnauth.switch(start=True)

    def init_create_vpn_eb_keys(self):
        """
        Creates a new keys in the SoftHSM token -> EB.
        :return:
        """
        if self.args.no_ejbca_install:
            logger.warning('EJBCA disabled, cannot generate keys')
            return 0

        self.tprint('\nEnigma Bridge service will generate new keys:')
        ret, out, err = self.ejbca.pkcs11_generate_default_key_set(softhsm=self.soft_config)

        if ret != 0:
            self.tprint(self.t.red('\nError generating new keys'))
            self.tprint('The installation has to be repeated later')

            self.tprint('\nError from the command:')
            self.tprint(''.join(out))
            self.tprint('\n')
            self.tprint(''.join(err))
            return 1
        return 0

    def init_create_vpn_users(self):
        """
        Create default VPN users, final steps
        :return: 
        """
        if self.args.no_ejbca_install:
            logger.warning('EJBCA disabled, cannot create VPN users')
            return 0

        self.ejbca.vpn_create_user(self.config.email, 'default')
        token = self.ejbca.vpn_create_p12_otp()
        self.config.p12_otp_superadmin = token

    def init_install_os_hooks(self):
        """
        Install OS hooks - cronjob for cert checking, on boot service for dynamic DNS
        :return: result
        """
        install_type = 'vpn'
        self.syscfg.install_onboot_check(install_type=install_type)
        self.syscfg.install_cron_renew(install_type=install_type)
        self.syscfg.install_cron_update(install_type=install_type)
        return 0

    def le_renewed(self):
        """
        Letsencrypt was renewed
        :return: 
        """
        Installer.le_renewed(self)
        self.nginx = nginx.Nginx(sysconfig=self.syscfg, audit=self.audit, write_dots=True)
        self.nginx.switch(restart=True)


def main():
    app = VpnInstaller()
    app.app_main()


if __name__ == '__main__':
    main()


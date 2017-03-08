#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cmd2 import Cmd
import argparse
import sys
import os
import math
import types
import traceback
import pid
import json
import time
import util
import random
import audit
import errors
import textwrap
from blessed import Terminal
from consts import *
from core import Core
from config import Config, EBSettings
from registration import Registration, InfoLoader
from softhsm import SoftHsmV1Config
from jboss import Jboss
from ejbca import Ejbca
from ebsysconfig import SysConfig
from letsencrypt import LetsEncrypt
from ebclient.registration import ENVIRONMENT_PRODUCTION, ENVIRONMENT_DEVELOPMENT, ENVIRONMENT_TEST
from pkg_resources import get_distribution, DistributionNotFound
from clibase import InstallerBase
import dbutil
import logging
import coloredlogs


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.ERROR)


class Installer(InstallerBase):
    """
    EnigmaBridge AWS command line interface
    """

    def __init__(self, *args, **kwargs):
        """
        Init core
        :param args:
        :param kwargs:
        :return:
        """
        InstallerBase.__init__(self, *args, **kwargs)
        self.last_le_port_open = False
        self.last_is_vpc = False

        # Init state
        self.reg_svc = None
        self.soft_config = None
        self.jboss = None
        self.ejbca = None
        self.mysql = None
        self.eb_cfg = None

        self.previous_registration_continue = False
        self.domain_is_ok = False
        self.first_run = self.is_first_run()
        self.init_started_time = None
        self.init_finished_success = None
        self.init_exception = None

        self.debug_simulate_vpc = False
        self.update_intro()

    def is_first_run(self):
        """
        Returns true if this is the first run - configuration is empty.
        :return:
        """
        try:
            config = Core.read_configuration()
            return config is None or config.has_nonempty_config()
        except:
            return True

    def update_intro(self):
        """
        Updates intro text for CLI header - adds version to it.
        :return:
        """
        self.intro = '-'*self.get_term_width() + \
                     ('\n    Enigma Bridge Installer command line interface (v%s) \n' % self.version) + \
                     '\n    usage - shows simple command list' + \
                     '\n    init  - initializes the key management system\n'

        if self.first_run:
            self.intro += '            run this when running for the first time\n'

        self.intro += '\n    More info: https://enigmabridge.com/amazonpki \n' + \
                      '-'*self.get_term_width()

    def cfg_get_raw_hostname(self):
        """
        Returns natural hostname of the machine - reachable over the internet.
        If there is no public hostname available, IPv4 address is returned.
        Used when DNS registration fails.
        :return:
        """
        # TODO: refactor to multi profiles, not just AWS
        return self.reg_svc.info_loader.ami_public_hostname

    def cfg_get_raw_ip(self):
        """
        Returns public IP address of the machine.
        May use profile dependent tools to figure this out - e.g., AWS tools.
        :return:
        """
        # TODO: refactor to multiple profiles, not just AWS
        if self.reg_svc is not None and self.reg_svc.info_loader is not None:
            return self.reg_svc.info_loader.ami_public_ip

        info = InfoLoader(audit=self.audit, sysconfig=self.syscfg)
        info.load()
        return info.ami_public_ip

    def get_db_type(self):
        """
        Returns DB type to use for the installation - EJBCA.
        Priority: command line argument, ENV[EJBCA_DB_TYPE], config, /opt/enigma config, None
        :return:
        """
        if self.args.db_type is not None:
            return self.args.db_type
        if 'EJBCA_DB_TYPE' in os.environ:
            return os.environ['EJBCA_DB_TYPE']
        if self.config is not None and self.config.ejbca_db_type is not None:
            return self.config.ejbca_db_type
        if self.eb_settings is not None and self.eb_settings.ejbca_db_type is not None:
            return self.eb_settings.ejbca_db_type
        return None

    def get_db_root_password(self):
        """
        Returns root password for the database. Required for MySQL server to create the databases.
        Priority: ENV[EJBCA_DB_ROOT_PASS], config, /opt/enigma, None
        :return:
        """
        if 'EJBCA_DB_ROOT_PASS' in os.environ:
            return os.environ['EJBCA_DB_ROOT_PASS']
        if self.config is not None and self.config.mysql_root_password is not None:
            return self.config.mysql_root_password
        if self.eb_settings is not None and self.eb_settings.mysql_root_password is not None:
            return self.eb_settings.mysql_root_password
        return None

    #
    # Install action
    #

    def do_dump_config(self, line):
        """Dumps the current configuration to the terminal"""
        config = Core.read_configuration()
        if config is None:
            self.tprint('None configuration is stored.')
            self.tprint('init was probably not called on this machine.')
        else:
            self.tprint(config.to_string())

    def do_usage(self, line):
        """Writes simple usage hints"""
        self.tprint('init   - initializes the PKI key management instance with new identity')
        self.tprint('renew  - renews publicly trusted certificate for secure web access')
        self.tprint('usage  - writes this usage info')

    def do_install(self, line):
        """Alias for init"""
        self.do_init(line)

    def init_load_settings(self):
        """
        Loads EB settings as a part of the init. If settings exist already, the backup is performed.
        :return:
        """
        self.config = Core.read_configuration()
        config_exists = self.config is not None and self.config.has_nonempty_config()
        self.previous_registration_continue = False

        # there may be 2-stage registration waiting to finish - continue with the registration
        if config_exists and self.config.two_stage_registration_waiting:
            self.tprint('\nThere is a previous unfinished registration for email: %s' % self.config.email)
            should_continue = self.ask_proceed(question='Do you want to continue with this registration? (y/n): ',
                                               support_non_interactive=True, non_interactive_return=self.PROCEED_NO)
            self.previous_registration_continue = should_continue

        if config_exists and not self.previous_registration_continue:
            self.tprint(self.t.red('\nWARNING! This is a destructive process!'))
            self.tprint(self.t.red('WARNING! The previous installation will be overwritten.\n'))
            should_continue = self.ask_proceed(support_non_interactive=True)
            if not should_continue:
                return self.return_code(1)

            self.tprint('\nWARNING! Configuration already exists in the file %s' % (Core.get_config_file_path()))
            self.tprint('The configuration will be overwritten by a new one (current config will be backed up)\n')
            should_continue = self.ask_proceed(support_non_interactive=True)
            if not should_continue:
                return self.return_code(1)

            # Backup the old config
            fname = Core.backup_configuration(self.config)
            self.tprint('Configuration has been backed up: %s\n' % fname)

        return 0

    def init_services(self):
        """
        Installer services initialization
        :return:
        """
        self.eb_cfg = Core.get_default_eb_config()
        if self.previous_registration_continue:
            self.config.eb_config = self.eb_cfg
        else:
            # New configuration is created
            # Some settings are migrated, e.g., mysql root password
            old_config = self.config
            self.config = Config(eb_config=self.eb_cfg)

            if old_config is not None and old_config.mysql_root_password is not None:
                self.config.mysql_root_password = old_config.mysql_root_password

        # Database settings.
        self.config.mysql_root_password = self.get_db_root_password()
        self.config.ejbca_db_type = self.get_db_type()
        self.audit.add_secrets(self.config.mysql_root_password)

        # Determine the environment we are going to use in EB.
        self.config.env = self.get_env()
        if self.config.env != ENVIRONMENT_PRODUCTION:
            pass  # Core.set_devel_endpoints(self.eb_cfg) # TODO: fix this

        # Initialize helper classes for registration & configuration.
        self.reg_svc = Registration(email=self.config.email, config=self.config,
                                    eb_config=self.eb_cfg, eb_settings=self.eb_settings,
                                    audit=self.audit, sysconfig=self.syscfg)

        self.soft_config = SoftHsmV1Config()
        self.mysql = dbutil.MySQL(sysconfig=self.syscfg, audit=self.audit, config=self.config,
                                  write_dots=True, root_passwd=self.get_db_root_password())
        self.jboss = Jboss(config=self.config, eb_config=self.eb_settings,
                           sysconfig=self.syscfg, audit=self.audit, write_dots=True)
        self.ejbca = Ejbca(print_output=True, staging=self.args.le_staging,
                           config=self.config, eb_config=self.eb_settings,
                           sysconfig=self.syscfg, audit=self.audit, jboss=self.jboss, mysql=self.mysql)
        return 0

    def init_prompt_user(self):
        """
        Prompt user for initial data as a part of the initialisation process.
        E.g., asks for the user e-mail.
        Takes installation continuation into consideration.
        :return:
        """
        if not self.previous_registration_continue:
            # Ask for email if we don't have any (e.g., previous unfinished reg).
            self.email = self.ask_for_email(is_required=self.reg_svc.is_email_required())
            if isinstance(self.email, types.IntType):
                return self.return_code(1, True)
            else:
                self.config.email = self.email

            # Ask user explicitly if he wants to continue with the registration process.
            # Terms & Conditions of the AMIs tells us to ask user whether we can connect to the servers.
            self.init_print_intro()
            should_continue = self.ask_proceed('Do you agree with the installation process '
                                               'as outlined above? (Y/n): ',
                                               support_non_interactive=True)
            if not should_continue:
                return self.return_code(1)

            self.cli_separator()
        else:
            self.email = self.config.email

        return 0

    def init_prepare_install(self):
        """
        Prepares installation - e.g., disables renew cron
        :return:
        """
        self.syscfg.remove_cron_renew()

    def init_test_environment(self):
        """
        Tests if the given environment corresponds to the profile set.
        E.g., if the profile is AMI, then it should be ready for deployment ( - JBoss already installed)
        TODO: extend with other profiles
        :return: result
        """
        if not self.ejbca.test_environment():
            self.tprint(self.t.red('\nError: Environment is damaged, some assets are missing for the key '
                                   'management installation. Cannot continue.'))
            return self.return_code(1)
        return 0

    def init_enigma_registration_prepare(self):
        """
        Prepares user registration to the EnigmaBridge - asks for the registration token, loads initial data.
        Handles also continued installation - interrupted previously to wait for auth challenge.
        :return: result
        """
        if self.previous_registration_continue and not self.noninteractive:
            tmp = 'Your validation challenge is in the ticket assigned to you in the ' \
                  'system https://enigmabridge.freshdesk.com for account %s.' % self.email
            self.tprint(self.wrap_term(single_string=True, max_width=self.get_term_width(), text=tmp))

            self.reg_svc.reg_token = self.ask_for_token()

        elif self.reg_svc.is_auth_needed():
            self.reg_svc.init_auth()
            Core.write_configuration(self.config)
            self.init_print_challenge_intro()
            self.reg_svc.reg_token = self.ask_for_token()

        else:
            # Init, but do not wait for token.
            self.reg_svc.init_auth()
        return 0

    def init_enigma_registration(self):
        """
        Handles user registration to the EnigmaBridge. Performs the actual registration call.
        :return: result, new_config
        """
        res = self.init_enigma_registration_prepare()
        if res != 0:
            return self.return_code(res)

        # Creates a new RSA key-pair identity
        # Identity relates to bound DNS names and username.
        # Requests for DNS manipulation need to be signed with the private key.
        self.reg_svc.new_identity(id_dir=CONFIG_DIR, backup_dir=CONFIG_DIR_OLD)

        # New client registration (new username, password, apikey).
        # This step may require email validation to continue.
        new_config = None
        try:
            new_config = self.reg_svc.new_registration()
        except Exception as e:
            logger.debug(traceback.format_exc())
            self.audit.audit_exception(e)
            logger.debug('Exception in registration: %s' % e)

            if self.reg_svc.is_auth_needed():
                self.tprint(self.t.red('Error in the registration, probably problem with the challenge. '))
            else:
                self.tprint(self.t.red('Error in the registration'))
            self.tprint('Please, try again. If problem persists, '
                        'please contact our support at https://enigmabridge.freshdesk.com/helpdesk/tickets/new')
            return self.return_code(14), None

        return 0, new_config

    def init_install_os_hooks(self):
        """
        Install OS hooks - cronjob for cert checking, on boot service for dynamic DNS
        :return: result
        """
        self.syscfg.install_onboot_check()
        self.syscfg.install_cron_renew()
        return 0

    def init_softhsm(self, new_config):
        """
        Initializes SoftHSM component
        :return: result
        """
        self.tprint('\n')

        soft_config_backup_location = self.soft_config.backup_current_config_file()
        if soft_config_backup_location is not None:
            self.tprint('EnigmaBridge PKCS#11 token configuration has been backed up to: %s'
                        % soft_config_backup_location)

        self.soft_config.configure(new_config)
        soft_config_file = self.soft_config.write_config()

        self.tprint('New EnigmaBridge PKCS#11 token configuration has been written to: %s\n' % soft_config_file)

        # Init the token
        backup_dir = self.soft_config.backup_previous_token_dir()
        if backup_dir is not None:
            self.tprint('EnigmaBridge PKCS#11 previous token database moved to: %s' % backup_dir)

        out, err = self.soft_config.init_token(user=self.jboss.get_user())
        self.tprint('EnigmaBridge PKCS#11 token initialization: %s' % out)
        return 0

    def init_add_softhsm_token(self, name='EnigmaBridgeToken', slot_id=0):
        """
        Adds SoftHSM crypto token to the EJBCA
        :return:
        """
        self.tprint('\nAdding an EnigmaBridge crypto token to your PKI instance:')
        ret, out, err = self.ejbca.ejbca_add_softhsm_token(softhsm=self.soft_config, name=name, slot_id=slot_id)
        if ret != 0:
            self.tprint('\nError in adding EnigmaBridge token to the PKI instance')
            self.tprint('You can add it manually in the PKI (EJBCA) admin page later')
            self.tprint('Pin for the EnigmaBridge token is 0000')
        else:
            self.tprint('\nEnigmaBridgeToken added to the PKI instance')
        return 0

    def init_create_new_eb_keys(self):
        """
        Creates a new keys in the SoftHSM token -> EB.
        Ready for use in the EJBCA for CA.
        :return:
        """
        self.tprint('\nEnigma Bridge service will generate keys for your crypto token:')
        ret, out, err = self.ejbca.pkcs11_generate_default_key_set(softhsm=self.soft_config)
        key_gen_cmds = [
            self.ejbca.pkcs11_get_generate_key_cmd(softhsm=self.soft_config,
                                                   bit_size=2048, alias='signKey', slot_id=0),
            self.ejbca.pkcs11_get_generate_key_cmd(softhsm=self.soft_config,
                                                   bit_size=2048, alias='defaultKey', slot_id=0),
            self.ejbca.pkcs11_get_generate_key_cmd(softhsm=self.soft_config,
                                                   bit_size=2048, alias='testKey', slot_id=0)
        ]

        if ret != 0:
            self.tprint('\nError generating new keys')
            self.tprint('You can do it later manually by calling')

            for tmpcmd in key_gen_cmds:
                self.tprint('  %s' % self.ejbca.pkcs11_get_command(tmpcmd))

            self.tprint('\nError from the command:')
            self.tprint(''.join(out))
            self.tprint('\n')
            self.tprint(''.join(err))
        else:
            self.tprint('\nEnigmaBridge tokens generated successfully')
            self.tprint('You can use these newly generated keys for your CA or generate another ones with:')
            for tmpcmd in key_gen_cmds:
                self.tprint('  %s' % self.ejbca.pkcs11_get_command(tmpcmd))
        return 0

    def init_database(self):
        """
        Initializes configured database
        :return:
        """
        db_type = self.get_db_type()
        self.audit.audit_value(key='db_type', value=db_type)

        if db_type == 'mysql':
            return self.init_mysql()

        return 0

    def init_mysql_install_start(self):
        """
        Installs database, enables after start, starts it.
        :return: 0 on success
        """
        installed = self.mysql.check_installed()
        if not installed:
            ret = self.mysql.install()
            if ret != 0:
                raise errors.SetupError('Error with mysql/mariadb installation')
        else:
            logger.debug('MySQL server already installed')

        ret = self.mysql.enable()
        if ret != 0:
            raise errors.SetupError('Error with setting mysql/mariadb to start after boot')

        running = self.mysql.check_running()
        if not running:
            ret = self.mysql.switch(start=True)
            if ret != 0:
                raise errors.SetupError('Error with mysql/mariadb start')
        else:
            logger.debug('MySQL server running')

        return 0

    def init_mysql_try_check_root_passwd(self):
        """
        Checks root password, returns true password is valid
        :return: True if password is valid, False otherwise
        """
        # MySQL password validity check
        root_passwd_valid = False
        try:
            root_passwd_valid = self.mysql.test_root_passwd()
        except Exception as e:
            self.audit.audit_exception(e)
            logger.debug('Exception in mysql password test: %s' % e)

        return root_passwd_valid

    def init_mysql(self):
        """
        Installs MySQL database in a secure way, enables it after start and stats it up.
        Root password is reset
        :return: 0 on success
        """
        self.init_mysql_install_start()

        # MySQL password validity check
        root_passwd_valid = self.init_mysql_try_check_root_passwd()

        # Password invalid, solution -> uninstall, do again.
        if not root_passwd_valid:
            self.tprint(self.t.red('\nError') + ': MySQL database has invalid root password configured, cannot connect')

            confirmation = self.ask_proceed_quit('Do you want me to reinstall the database? '
                                                 'All data will be lost. (y/n/q): ')
            if confirmation != self.PROCEED_YES:
                raise errors.SetupError('Cannot connect to the database')

            # Turn it off, uninstall (double is intended, mysql55-server is removed in the second one)
            self.mysql.switch(stop=True)
            self.mysql.uninstall()
            self.mysql.uninstall()
            self.mysql.remove_data()
            self.init_mysql_install_start()

            self.config.mysql_root_password = ''
            self.mysql.root_passwd = ''

            root_passwd_valid = self.init_mysql_try_check_root_passwd()
            if not root_passwd_valid:
                self.tprint(self.t.red('\nError') + ': MySQL database has invalid root password configured, '
                                                    'cannot continue.')
                raise errors.SetupError('Cannot connect to the database')

        # Change root password to a new one.
        new_root_password = util.random_password(16)
        ret = self.mysql.change_root_password(new_password=new_root_password)
        if ret != 0:
            raise errors.SetupError('Error with mysql/mariadb root password change')

        # Root password has been updated
        self.config.mysql_root_password = new_root_password
        self.mysql.root_passwd = new_root_password
        Core.write_configuration(self.config)

        # Secure configuration
        ret = self.mysql.configure()
        if ret != 0:
            raise errors.SetupError('Error in configuring mysql/mariadb')

        return 0

    def init_le_install(self, ejbca=None):
        """
        Installs LetsEncrypt certificate to the EJBCA.
        :param ejbca:
        :return: result
        """
        if ejbca is None:
            ejbca = self.ejbca

        le_certificate_installed = self.le_install(self.ejbca)

        self.tprint('\n')
        self.cli_separator()
        self.cli_sleep(3)

        if le_certificate_installed == 0:
            if not self.domain_is_ok:
                self.tprint('  \nThere was a problem in registering new domain names for you system')
                self.tprint('  Please get in touch with support@enigmabridge.com and we will try to resolve the problem')
        else:
            self.tprint('  \nTrusted HTTPS certificate was not installed, most likely reason is port '
                        '443 being closed by a firewall')
            self.tprint('  For more info please check https://enigmabridge.com/support/aws13073')
            self.tprint('  We will keep re-trying every 5 minutes.')
            self.tprint('\nMeantime, you can access the system at:')
            self.tprint('     https://%s:%d/ejbca/adminweb/' % (self.cfg_get_raw_hostname(), self.ejbca.PORT))
            self.tprint('WARNING: you will have to override web browser security alerts.')
        return 0

    def init_install_ejbca_intro(self):
        """
        Shows text info before EJBCA installation starts
        :return:
        """
        self.tprint('Going to install PKI system')
        self.tprint('  This may take 15 minutes or less. Please, do not interrupt the installation')
        self.tprint('  and wait until the process completes.\n')

    def init_jboss(self):
        """
        Initializes JBoss
        :return:
        """
        ret = self.jboss.install()
        if ret != 0:
            raise errors.SetupError('Cannot install JBoss package')

        self.jboss.configure_server()
        self.jboss.fix_privileges()

        # OS configuration
        ret = self.jboss.setup_os()
        if ret != 0:
            raise errors.SetupError('Cannot configure OS for the JBoss server')

        # Starting VPN server
        ret = self.jboss.enable()
        if ret != 0:
            raise errors.SetupError('Cannot set JBoss server to start after boot')
        return 0

    def init_install_ejbca(self, new_config=None):
        """
        Installs EJBCA
        :return: result
        """
        if new_config is None:
            new_config = self.config

        self.init_install_ejbca_intro()
        self.init_jboss()

        self.ejbca.set_config(new_config)
        self.ejbca.set_domains(new_config.domains)
        self.ejbca.reg_svc = self.reg_svc

        self.ejbca.configure()

        if self.ejbca.ejbca_install_result != 0:
            self.tprint('\nPKI installation error. Please try again.')
            return self.return_code(1)

        Core.write_configuration(self.ejbca.config)
        self.tprint('\nPKI installed successfully.')
        return 0

    def init_celebrate(self):
        """
        Show all done
        :return:
        """
        self.tprint(self.t.underline_green('[OK] System installation is completed'))

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
        self.tprint(self.t.underline('Please setup your computer for secure connections to your PKI '
                                     'key management system:'))
        time.sleep(0.5)

        public_hostname = self.ejbca.hostname if self.domain_is_ok else self.cfg_get_raw_hostname()
        self.tprint('\nDownload p12 file: %s' % new_p12)
        self.tprint('  scp -i <your_Amazon_PEM_key> ec2-user@%s:%s .' % (public_hostname, new_p12))
        self.tprint_sensitive('  Key import password is: %s' % self.ejbca.superadmin_pass)
        self.tprint('\nThe following page can guide you through p12 import: https://enigmabridge.com/support/aws13076')
        self.tprint('Once you import the p12 file to your computer browser/keychain you can connect to the PKI '
                    'admin interface:')

        if self.domain_is_ok:
            for domain in new_config.domains:
                self.tprint('  https://%s:%d' % (domain, self.ejbca.PORT))
        else:
            self.tprint('  https://%s:%d' % (self.cfg_get_raw_hostname(), self.ejbca.PORT))

    def init_test_ejbca_ports_routable(self, public=False, with_server=True, host=None, *args, **kwargs):
        """
        Testing if EJBCA port is routable from the public IP address.
        If server is True the echo server is spawned on the local server
        :param public:
        :param with_server:
        :param host:
        :return: True if routable, false if not, None if cannot determine
        """
        host = util.defval(host, self.cfg_get_raw_ip())
        port = self.ejbca.PORT_PUBLIC if public else self.ejbca.PORT
        return util.test_port_routable(host=host, port=port, with_server=with_server, audit=self.audit)

    def init_test_ports_pre_install_res(self, host=None, *args, **kwargs):
        """
        Tests ports routability before installation starts, returns failed port array.
        This method can be extended.
        :return: list of failed ports
        """
        host = util.defval(host, self.cfg_get_raw_ip())
        failed_ports = []

        admin_ok = self.init_test_ejbca_ports_routable(host=host, with_server=True, public=False)
        if not admin_ok:
            failed_ports.append(util.Port(port=Ejbca.PORT, tcp=True, service='EJBCA'))

        public_ok = self.init_test_ejbca_ports_routable(host=host, with_server=True, public=True)
        if not public_ok:
            failed_ports.append(util.Port(port=Ejbca.PORT_PUBLIC, tcp=True, service='EJBCA'))

        return failed_ports

    def init_test_ports_pre_install(self):
        """
        Tests ports routability before installation starts.
        Performs the check
        :return: 0 if it is OK and we should continue, quit otherwise
        """
        if self.last_is_vpc:
            return

        host = self.cfg_get_raw_ip()
        attempts = 0
        user_response = 2

        while user_response == 2:
            failed_ports = self.init_test_ports_pre_install_res(host=host)
            self.audit.audit_value(key='failed_ports', value=failed_ports)

            if len(failed_ports) > 0:
                user_response = self.init_print_unreachable_ports(ports=failed_ports, attempt=attempts)
                attempts += 1
            else:
                return 0

        return user_response

    def init_print_unreachable_ports(self, ports, attempt=0):
        """
        Prints an error about unreachable ports during the installation
        :param ports:
        :param attempt:
        :return: return 0 if OK, 1 for fail, 2 for try again.
        """
        if ports is None or len(ports) == 0:
            return 0

        self.tprint('\nUnreachable ports detected:')
        for port in ports:
            self.tprint('  - %s' % str(port))

        if attempt == 0:
            self.tprint('\nIn order to make system work properly please enable the following ports on the firewall, ')
            self.tprint('or please consult AWS security groups')

        answer = self.ask_options('Do you want to continue with the installation (y), quit (q) or try again (a)? ',
                                  allowed_options=['y', 'q', 'a'], support_non_interactive=True,
                                  non_interactive_return='y')
        if answer == 'y':
            return 0
        elif answer == 'q':
            return 1
        else:
            return 2

    def init_test_ejbca_ports_reachability(self, check_public=False, with_server=False):
        """
        Tests main EJBCA admin port reachability. Done after EJBCA is installed - service is assumed to be running.
        :param: check_public public port not checked by default
        :return:
        """
        # Test if EJBCA is reachable on outer interface
        # The test is performed only if not in VPC. Otherwise it makes no sense to check public IP for 8443.
        if self.last_is_vpc:
            return

        ejbca_open = self.init_test_ejbca_ports_routable(public=False, with_server=with_server)
        if not ejbca_open:
            self.cli_sleep(2)
            self.init_print_ejbca_unreachable_error()
            return

        if not check_public:
            return

        ejbca_public_open = self.init_test_ejbca_ports_routable(public=True, with_server=with_server)
        if not ejbca_public_open:
            self.cli_sleep(2)
            self.init_print_ejbca_unreachable_public_error()
            return

    def init_print_ejbca_unreachable_error(self):
        """
        Prints error when EJBCA admin ports are not reachable
        :return:
        """
        self.tprint('\nWarning! The PKI port %d is not reachable on the public IP address %s'
                    % (self.ejbca.PORT, self.cfg_get_raw_ip()))
        self.tprint('Make sure both ports are open and available: %d, %d' % (self.ejbca.PORT, self.ejbca.PORT_PUBLIC))
        self.tprint('If you cannot connect to the PKI kye management interface, consider reconfiguring the '
                    'AWS Security Groups')
        self.tprint('Please get in touch with our support via https://enigmabridge.freshdesk.com/helpdesk/tickets/new')

    def init_print_ejbca_unreachable_public_error(self):
        """
        Prints error when EJBCA admin ports are not reachable
        :return:
        """
        self.tprint('\nWarning! The PKI public port %d is not reachable on the public IP address %s'
                    % (self.ejbca.PORT_PUBLIC, self.cfg_get_raw_ip()))
        self.tprint('If you cannot connect to the PKI kye management interface, consider reconfiguring the '
                    'AWS Security Groups')
        self.tprint('Please get in touch with our support via https://enigmabridge.freshdesk.com/helpdesk/tickets/new')

    def init_main_try(self):
        """
        Main installer block, called from the global try:
        :return:
        """
        self.init_services()

        # Get registration options and choose one - network call.
        self.reg_svc.load_auth_types()

        # Show email prompt and intro text only for new initializations.
        res = self.init_prompt_user()
        if res != 0:
            self.return_code(res)

        # Disable services which may interfere installation.
        self.init_prepare_install()

        # System check proceeds (mem, network).
        # We do this even if we continue with previous registration, to have fresh view on the system.
        # Check if we have EJBCA resources on the drive
        res = self.init_test_environment()
        if res != 0:
            self.return_code(res)

        # Determine if we have enough RAM for the work.
        # If not, a new swap file is created so the system has at least 2GB total memory space
        # for compilation & deployment.
        res = self.install_check_memory(syscfg=self.syscfg)
        if res != 0:
            return self.return_code(res)

        # Preferred LE method? If set...
        self.last_is_vpc = False

        # Lets encrypt reachability test, if preferred method is DNS - do only one attempt.
        # We test this to detect VPC also. If 443 is reachable, we are not in VPC
        res, args_le_preferred_method = self.init_le_vpc_check(self.get_args_le_verification(),
                                                               self.get_args_vpc(), reg_svc=self.reg_svc)
        if res != 0:
            return self.return_code(res)

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

        # Dump config & SoftHSM
        conf_file = Core.write_configuration(new_config)
        self.tprint('New configuration was written to: %s\n' % conf_file)

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
        res = self.init_create_new_eb_keys()
        if res != 0:
            return self.return_code(res)

        # Add SoftHSM crypto token to EJBCA as a hard token
        res = self.init_add_softhsm_token()
        if res != 0:
            return self.return_code(res)

        # LetsEncrypt enrollment
        res = self.init_le_install()
        if res != 0:
            return self.return_code(res)

        # Install to the OS - cron job & on boot service
        res = self.init_install_os_hooks()
        if res != 0:
            return self.return_code(res)

        self.tprint('')
        self.init_celebrate()
        self.cli_sleep(3)
        self.cli_separator()

        # Finalize, P12 file & final instructions
        new_p12 = self.ejbca.copy_p12_file()
        self.init_show_p12_info(new_p12=new_p12, new_config=new_config)

        # Test if main admin port of EJBCA is reachable.
        self.init_test_ejbca_ports_reachability()

        self.cli_sleep(5)
        return self.return_code(0)

    def init_install_intro_text(self):
        """
        Shows installation intro text when installation starts.
        :return:
        """
        self.tprint('Going to install PKI system and enrol it to the Enigma Bridge FIPS140-2 encryption service.\n')

    def do_init(self, line):
        """
        Initializes the EB client machine, new identity is assigned.
         - New EnigmaBridge identity is fetched
         - EnigmaBridge PKCS#11 Proxy is configured, new token is initialized
         - EJBCA is reinstalled with PKCS#11 support, with new certificates
        Previous configuration data is backed up.
        :type line: object
        """
        # Main try-catch block for the overall init operation.
        # noinspection PyBroadException
        try:
            self.init_started_time = time.time()
            if not self.check_root() or not self.check_pid():
                return self.return_code(1)

            self.audit.set_flush_enabled(True)
            self.init_install_intro_text()

            # EB Settings read. Optional.
            self.load_base_settings()

            # Configuration read, if any
            ret = self.init_load_settings()
            if ret != 0:
                return self.return_code(ret)

            ret = self.init_main_try()
            if ret != 0:
                return self.return_code(ret)

            self.init_finished_success = True

        except Exception as e:
            logger.debug(traceback.format_exc())
            self.audit.audit_exception(e)
            self.init_exception = str(e)
            self.tprint('Exception in the installation process, cannot continue.')
            self.install_analysis_send()

        self.send_install_status()
        return self.return_code(1)

    def init_get_install_status(self):
        """
        Returns install status as dict
        :return:
        """
        return {
            'error': 'success (ok)' if self.init_finished_success else self.init_exception,
            'status': 0x9000 if self.init_finished_success else 0x6f00,
            'duration': int(time.time() - self.init_started_time) if self.init_started_time is not None else 0,
            'email': self.config.email if self.config is not None else None,
            'ip': self.cfg_get_raw_ip(),
            'version': self.version,
            'time': time.time(),
            'vpc': self.last_is_vpc,
            'password': self.ejbca.superadmin_pass if self.ejbca is not None else None
        }

    def send_install_status(self):
        """
        Submits installation status to the EB
        :return:
        """
        status_data = self.init_get_install_status()

        # Install status won't fly if registration did not finish
        if self.config is None or self.config.email is None or self.config.apikey is None:
            logger.debug('Not sending install status, registration is not finished')
            return False

        for attempt in range(3):
            try:
                return self.reg_svc.install_status(status=status_data)

            except Exception as e:
                logger.debug('Exception in sending install status: %s' % e)

        return False

    def init_send_audit_log(self):
        """
        Sends the audit log
        :return:
        """
        if self.reg_svc is None:
            self.reg_svc = Registration(email=self.config.email, config=self.config,
                                        eb_config=self.eb_cfg, eb_settings=self.eb_settings,
                                        audit=self.audit, sysconfig=self.syscfg)
        for attempt in range(3):
            try:
                collision_src = '%s;%s;%s;%s;' % (random.randint(0, 2 ** 64 - 1), int(time.time()),
                                                  self.cfg_get_raw_ip(), self.version)

                logger.debug('Generating collisions, src: %s' % collision_src)
                collision_start = time.time()
                collision_nonce = util.collision_generator(collision_src, prefix_len=20)
                collision_total = '%s%s' % (collision_src, collision_nonce)
                logger.debug('Collision generated, nonce: %d' % collision_nonce)

                self.audit.audit_evt('collision-generated', nonce=collision_nonce, src=collision_src,
                                     elapsed=time.time() - collision_start)

                audit_json = self.audit.get_content()
                return self.reg_svc.send_audit_logs(preimage=collision_total, log=audit_json)

            except Exception as e:
                logger.debug('Exception in sending audit log: %s' % e)

        return False

    def install_analysis_send(self):
        """
        Prompts user to send audit file for analysis, if allowed, logs are uploaded
        :return:
        """
        confirmation = self.ask_proceed_quit('Do you want to submit audit log file for analysis to help '
                                             'resolve problems? (y/n): ', support_non_interactive=True,
                                             non_interactive_return=self.PROCEED_YES, quit_enabled=False)
        if confirmation != self.PROCEED_YES:
            return 0

        self.tprint('Please wait for a while, generating report...')
        return self.init_send_audit_log()

    def get_usr_reg_type(self):
        """
        Returns EB user registration type.
        Priority: ENV[EB_USER_REG_TYPE], args, /opt/enigma, None
        :return:
        """
        if 'EB_USER_REG_TYPE' in os.environ:
            return os.environ['EB_USER_REG_TYPE']
        if self.args is not None and self.args.reg_type is not None:
            return self.args.reg_type
        if self.eb_settings is not None and self.eb_settings.user_reg_type is not None:
            return self.eb_settings.user_reg_type
        return None

    def get_usr_reg_token(self):
        """
        Returns EB user registration token.
        Priority: ENV[EB_USER_REG_TOKEN], args, /opt/enigma, None
        :return:
        """
        if 'EB_USER_REG_TOKEN' in os.environ:
            return os.environ['EB_USER_REG_TOKEN']
        if self.args is not None and self.args.reg_token is not None:
            return self.args.reg_token
        if self.eb_settings is not None and self.eb_settings.user_reg_token is not None:
            return self.eb_settings.user_reg_token
        return None

    def load_base_settings(self):
        """
        Loads EB settings - defining the image / host VM.
        :return:
        """
        self.eb_settings, eb_aws_settings_path = Core.read_settings()
        self.user_reg_type = self.get_usr_reg_type()
        self.user_reg_token = self.get_usr_reg_token()

        if self.eb_settings is None:
            self.eb_settings = EBSettings()

        if self.user_reg_type is not None:
            self.eb_settings.user_reg_type = self.user_reg_type
        if self.user_reg_token is not None:
            self.eb_settings.user_reg_token = self.user_reg_token

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
        self.tprint('  - generate a dynamic DNS name (e.g., cambridge1.pki.enigmabridge.com);')
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
        text = 'In order to continue with the installation we need your consent with the network ' \
               'communication the instance will be doing during the installation as outlined in' \
               'the description above'
        self.tprint(self.wrap_term(single_string=True, max_width=80,text=text))

        self.tprint('')

    def init_le_vpc_check(self, args_le_preferred_method, args_is_vpc, reg_svc):
        """
        Checks if LE port is accessible - determines if the machine has publicly routable IP address with
         allowed port. Otherwise VPC question is asked. LE then uses DNS verification method.

        :param args_le_preferred_method:
        :param args_is_vpc:
        :param reg_svc:
        :return:
        """
        port_ok = self.le_check_port(critical=False, one_attempt=args_le_preferred_method == LE_VERIFY_DNS)
        if not port_ok and args_le_preferred_method != LE_VERIFY_DNS:
            return self.return_code(10), None

        # Is it VPC?
        # If user explicitly selects VPC then this is not printed
        # Otherwise we have to ask, because it can be just the case 443 is firewalled.
        if args_is_vpc is None and not self.last_le_port_open:
            self.cli_separator()
            self.tprint('\n - TCP port 443 was not reachable on the public IP %s' % self.cfg_get_raw_ip())
            self.tprint(' - You are probably behind NAT, in a virtual private cloud (VPC) or firewalled by other means')
            self.tprint(' - LetsEncrypt validation will now use DNS method\n')
            args_le_preferred_method = LE_VERIFY_DNS

            self.last_is_vpc = self.ask_proceed('Are you in VPC / behind firewall / NAT ?\n'
                                                'If yes, we will configure your private IP %s '
                                                'in the DNS (y=VPC / n=public): ' % reg_svc.info_loader.ami_local_ip)
            self.cli_separator()

        if args_is_vpc == 1:
            self.last_is_vpc = True
        elif args_is_vpc == 0:
            self.last_is_vpc = False

        # Test conflict between VPC and LE verification
        if self.last_is_vpc and args_le_preferred_method != LE_VERIFY_DNS:
            self.tprint('\nError: LetsEncrypt verification method has to be DNS if 443 is unreachable, overriding')
            args_le_preferred_method = LE_VERIFY_DNS

        return 0, args_le_preferred_method

    def init_domains_check(self, reg_svc=None):
        """
        Diplays domains registered for this host, checks if the domain registration went well.
        :param reg_svc:
        :return:
        """
        domain_is_ok = False
        domain_ignore = False
        domain_ctr = 0
        while not domain_is_ok and domain_ctr < 3:
            try:
                new_config = reg_svc.new_domain()
                new_config = reg_svc.refresh_domain()

                if new_config.domains is not None and len(new_config.domains) > 0:
                    domain_is_ok = True
                    self.tprint('\nNew domains registered for this host: ')
                    for domain in new_config.domains:
                        self.tprint('  - %s' % domain)
                    self.tprint('')

            except Exception as e:
                domain_ctr += 1
                logger.debug(traceback.format_exc())

                self.audit.audit_exception(e)
                if self.noninteractive:
                    if domain_ctr >= self.args.attempts:
                        break
                else:
                    self.tprint(self.t.red('\nError during domain registration, no dynamic domain will be assigned'))
                    should_continue = self.ask_proceed('Do you want to try again? (Y/n): ')
                    if not should_continue:
                        break

        # Is it OK if domain assignment failed?
        if not domain_is_ok:
            if domain_ignore:
                self.tprint('\nDomain could not be assigned, installation continues. You can try domain reassign later')
            else:
                self.tprint('\nDomain could not be assigned, installation aborted')
                return self.return_code(1), None

        return self.return_code(0), domain_is_ok

    def init_print_challenge_intro(self):
        """
        Prints text challenge to the user to copy registration token from the support system.
        :return:
        """
        self.cli_separator()
        self.tprint('')

        tmp = 'In order to complete your registration as an Enigma Bridge client, you need to enter a ' \
              'challenge. We have created this token in our support system at ' \
              'https://enigmabridge.freshdesk.com/helpdesk/tickets'
        self.tprint(self.wrap_term(single_string=True, max_width=self.get_term_width(), text=tmp))

        self.tprint('\nPlease follow these steps to access the token:')
        self.tprint('  1. Create an account in our support system for %s.' % self.email)
        self.tprint('       An invitation with a direct link should be in your mailbox.')
        self.tprint('  2. You will receive a new ticket notification. Open the ticket link.')
        self.tprint('  3. Copy the challenge from the ticket below.\n')

    #
    # Other CLI actions, renew, on boot, ...
    #

    def do_check_memory(self, args):
        """Check if there is enough memory in the system, adds a new swapfile if not"""
        self.install_check_memory(self.syscfg)

    def do_renew(self, arg):
        """Renews LetsEncrypt certificates used for the JBoss"""
        if not self.check_root() or not self.check_pid():
            return self.return_code(1)

        self.audit.set_flush_enabled(True)
        self.load_base_settings()
        config = Core.read_configuration()
        if config is None or not config.has_nonempty_config():
            self.tprint('\nError! Enigma config file not found %s' % (Core.get_config_file_path()))
            self.tprint(' Cannot continue. Have you run init already?\n')
            return self.return_code(1)

        domains = config.domains
        if domains is None or not isinstance(domains, types.ListType) or len(domains) == 0:
            self.tprint('\nError! No domains found in the configuration.')
            self.tprint(' Cannot continue. Did init complete successfully?')
            return self.return_code(1)

        # Argument override / reconfiguration
        args_le_preferred_method = self.get_args_le_verification()
        args_is_vpc = self.get_args_vpc()

        if args_le_preferred_method is not None and args_le_preferred_method != config.le_preferred_verification:
            self.tprint('\nOverriding LetsEncrypt preferred method, settings: %s, new: %s'
                        % (config.le_preferred_verification, args_le_preferred_method))
            config.le_preferred_verification = args_le_preferred_method

        if args_is_vpc is not None and args_is_vpc != config.is_private_network:
            self.tprint('\nOverriding is private network settings, settings.private: %s, new.private: %s'
                        % (config.is_private_network, args_is_vpc))
            config.is_private_network = args_is_vpc == 1

        if config.is_private_network \
                and args_le_preferred_method is not None \
                and args_le_preferred_method != LE_VERIFY_DNS:
            self.tprint('\nError, conflicting settings: VPC=1, LE method != DNS')
            return self.return_code(1)

        # Update configuration
        Core.write_configuration(config)

        # If there is no hostname, enrollment probably failed.
        eb_cfg = Core.get_default_eb_config()

        # Registration - for domain updates. Identity should already exist.
        reg_svc = Registration(email=config.email, eb_config=eb_cfg, config=config, debug=self.args.debug,
                               audit=self.audit, sysconfig=self.syscfg)
        ret = reg_svc.load_identity()
        if ret != 0:
                self.tprint('\nError! Could not load identity (key-pair is missing)')
                return self.return_code(3)

        # EJBCA
        mysql = dbutil.MySQL(sysconfig=self.syscfg, audit=self.audit, config=self.config,
                             write_dots=True, root_passwd=self.get_db_root_password())
        jboss = Jboss(config=config, eb_config=self.eb_settings, sysconfig=self.syscfg, audit=self.audit)
        ejbca = Ejbca(print_output=True, jks_pass=config.ejbca_jks_password, config=config, eb_config=self.eb_settings,
                      staging=self.args.le_staging, sysconfig=self.syscfg, audit=self.audit, jboss=jboss, mysql=mysql)
        ejbca.set_domains(config.ejbca_domains)
        ejbca.reg_svc = reg_svc

        ejbca_host = ejbca.hostname

        le_test = LetsEncrypt(staging=self.args.le_staging)
        enroll_new_cert = ejbca_host is None or len(ejbca_host) == 0 or ejbca_host == 'localhost'
        if enroll_new_cert:
            ejbca.set_domains(domains)
            ejbca_host = ejbca.hostname

        if not enroll_new_cert:
            enroll_new_cert = le_test.is_certificate_ready(domain=ejbca_host) != 0

        # Test LetsEncrypt port - only if in non-private network
        require_443_test = True
        if config.is_private_network:
            require_443_test = False
            self.tprint('\nInstallation done on private network, skipping TCP port 443 check')

        if config.get_le_method() == LE_VERIFY_DNS:
            require_443_test = False
            self.tprint('\nPreferred LetsEncrypt verification method is DNS, skipping TCP port 443 check')

        if require_443_test:
            port_ok = self.le_check_port(critical=True)
            if not port_ok:
                return self.return_code(10)

        ret = 0
        if enroll_new_cert:
            # Enroll a new certificate
            ret = self.le_install(ejbca)
        else:
            # Renew the certs
            ret = self.le_renew(ejbca)
        return self.return_code(ret)

    def do_onboot(self, line):
        """Command called by the init script/systemd on boot, takes care about IP re-registration"""
        if not self.check_root() or not self.check_pid():
            return self.return_code(1)

        self.audit.set_flush_enabled(True)
        try:
            config = Core.read_configuration()
            if config is None or not config.has_nonempty_config():
                self.tprint('\nError! Enigma config file not found %s' % (Core.get_config_file_path()))
                self.tprint(' Cannot continue. Have you run init already?\n')
                return self.return_code(2)

            eb_cfg = Core.get_default_eb_config()
            reg_svc = Registration(email=config.email, eb_config=eb_cfg, config=config, debug=self.args.debug,
                                   audit=self.audit, sysconfig=self.syscfg)
            domains = config.domains
            if domains is not None and isinstance(domains, types.ListType) and len(domains) > 0:
                self.tprint('\nDomains currently registered: ')
                for dom in config.domains:
                    self.tprint('  - %s' % dom)
                self.tprint('')

            if config.ejbca_hostname is not None:
                self.tprint('Domain used for your PKI system: %s\n' % config.ejbca_hostname)

            # Identity load (keypair)
            ret = reg_svc.load_identity()
            if ret != 0:
                self.tprint('\nError! Could not load identity (key-pair is missing)')
                return self.return_code(3)

            # IP has changed?
            if config.is_private_network:
                if config.last_ipv4_private is not None:
                    self.tprint('Last local IPv4 used for domain registration: %s' % config.last_ipv4_private)
                self.tprint('Current local IPv4: %s' % reg_svc.info_loader.ami_local_ip)
            else:
                if config.last_ipv4 is not None:
                    self.tprint('Last IPv4 used for domain registration: %s' % config.last_ipv4)
                self.tprint('Current IPv4: %s' % self.cfg_get_raw_ip())

            # Assign a new dynamic domain for the host
            domain_is_ok = False
            domain_ctr = 0
            new_config = config
            while not domain_is_ok:
                try:
                    new_config = reg_svc.refresh_domain()

                    if new_config.domains is not None and len(new_config.domains) > 0:
                        domain_is_ok = True
                        self.tprint('\nNew domains registered for this host: ')
                        for domain in new_config.domains:
                            self.tprint('  - %s' % domain)
                        self.tprint('')

                except Exception as e:
                    domain_ctr += 1
                    logger.debug(traceback.format_exc())

                    self.audit.audit_exception(e)
                    self.tprint('\nError during domain registration, no dynamic domain will be assigned')
                    if self.noninteractive:
                        if domain_ctr >= self.args.attempts:
                            break
                    else:
                        should_continue = self.ask_proceed('Do you want to try again? (Y/n): ')
                        if not should_continue:
                            break

            # Is it OK if domain assignment failed?
            if not domain_is_ok:
                self.tprint('\nDomain could not be assigned. You can try domain reassign later.')
                return self.return_code(1)

            new_config.last_ipv4 = self.cfg_get_raw_ip()
            new_config.last_ipv4_private = reg_svc.info_loader.ami_local_ip

            # Is original hostname used in the EJBCA in domains?
            if new_config.ejbca_hostname is not None \
                    and not new_config.ejbca_hostname_custom \
                    and new_config.ejbca_hostname not in new_config.domains:
                self.tprint('\nWarning! Returned domains do not correspond to the domain '
                            'used during EJBCA installation %s' % new_config.ejbca_hostname)
                self.tprint('\nThe PKI instance must be redeployed. This operations is not yet supported, please email '
                            'to support@enigmabridge.com')

            Core.write_configuration(new_config)
            return self.return_code(0)

        except Exception as ex:
            logger.debug(traceback.format_exc())
            self.audit.audit_exception(ex)
            self.tprint('Exception in the domain registration process, cannot continue.')

        return self.return_code(1)

    def do_change_hostname(self, line):
        """Changes hostname of the EJBCA installation"""
        self.tprint('This functionality is not yet implemented')
        self.tprint('Basically, its needed:\n '
                    '- edit conf/web.properties and change hostname there\n'
                    ' - ant deployear in EJBCA to redeploy EJBCA to JBoss with new settings (preserves DB)\n'
                    ' - edit /etc/enigma/config.json ejbca_hostname field\n'
                    ' - edit /etc/enigma/config.json ejbca_hostname_custom to true\n'
                    ' - call renew command')
        return self.return_code(1)

    def do_undeploy_ejbca(self, line):
        """Undeploys EJBCA without any backup left"""
        if not self.check_root() or not self.check_pid():
            return self.return_code(1)

        try:
            self.load_base_settings()
            self.audit.set_flush_enabled(True)
            self.tprint('Going to undeploy and remove EJBCA from the system')
            self.tprint('WARNING! This is a destructive process!')
            should_continue = self.ask_proceed(support_non_interactive=True)
            if not should_continue:
                return self.return_code(1)

            self.tprint('WARNING! This is the last chance.')
            should_continue = self.ask_proceed(support_non_interactive=True)
            if not should_continue:
                return self.return_code(1)

            config = Core.read_configuration()
            mysql = dbutil.MySQL(sysconfig=self.syscfg, audit=self.audit, config=self.config,
                                 write_dots=True, root_passwd=self.get_db_root_password())
            jboss = Jboss(config=config, eb_config=self.eb_settings, sysconfig=self.syscfg, audit=self.audit)
            ejbca = Ejbca(print_output=True, staging=self.args.le_staging, config=config, eb_config=self.eb_settings,
                          sysconfig=self.syscfg, audit=self.audit, jboss=jboss, mysql=mysql)

            self.tprint(' - Undeploying PKI System (EJBCA) from the application server')
            ejbca.undeploy()
            ejbca.jboss_restart()

            self.tprint('\nDone.')
            return self.return_code(0)

        except Exception as ex:
            logger.debug(traceback.format_exc())
            self.audit.audit_exception(ex)
            self.tprint('Exception in the undeploy process.')
            raise

    def do_test443(self, line):
        """Tests LetsEncrypt 443 port"""
        port_ok = self.le_check_port(critical=True)
        self.tprint('Check successful: %s' % ('yes' if port_ok else 'no'))
        return self.return_code(0 if port_ok else 1)

    def do_test_ejbca_ports(self, line):
        """Tests if EJBCA ports are accessible"""
        public_ip = self.cfg_get_raw_ip()
        self.tprint('Testing IP: %s, ports: %s, %s' % (public_ip, Ejbca.PORT, Ejbca.PORT_PUBLIC))

        # phase 1 - assume server is running.
        succ_admin = util.test_port_open(host=public_ip, port=Ejbca.PORT, test_upper_read_write=False)
        self.tprint('Port %s, server running, reachable: %s' % (Ejbca.PORT, succ_admin))

        succ_publ = util.test_port_open(host=public_ip, port=Ejbca.PORT_PUBLIC, test_upper_read_write=False)
        self.tprint('Port %s, server running, reachable: %s' % (Ejbca.PORT_PUBLIC, succ_publ))

        if not succ_admin:
            succ_admin2 = False
            try:
                succ_admin2 = util.test_port_open_with_server(host=public_ip, port=Ejbca.PORT)
            except:
                logger.debug(traceback.format_exc())
            self.tprint('Port %s, echo server, reachable: %s' % (Ejbca.PORT, succ_admin2))

        if not succ_publ:
            succ_publ2 = False
            try:
                succ_publ2 = util.test_port_open_with_server(host=public_ip, port=Ejbca.PORT_PUBLIC)
            except:
                logger.debug(traceback.format_exc())
            self.tprint('Port %s, echo server, reachable: %s' % (Ejbca.PORT_PUBLIC, succ_publ2))

    #
    # Helpers
    #

    def le_check_port(self, ip=None, letsencrypt=None, critical=False, one_attempt=False):
        if ip is None:
            info = InfoLoader(audit=self.audit, sysconfig=self.syscfg)
            info.load()
            ip = info.ami_public_ip

        self.last_le_port_open = False
        if letsencrypt is None:
            letsencrypt = LetsEncrypt(staging=self.args.le_staging)

        self.tprint('\nChecking if port %d is open for LetsEncrypt, ip: %s' % (letsencrypt.PORT, ip))
        ok = letsencrypt.test_port_open(ip=ip)

        # This is the place to simulate VPC during install
        if self.debug_simulate_vpc:
            ok = False

        if ok:
            self.last_le_port_open = True
            return True

        self.tprint('\nLetsEncrypt port %d is firewalled, please make sure it is reachable on the public interface %s'
                    % (letsencrypt.PORT, ip))
        self.tprint('Please check AWS Security Groups - Inbound firewall rules for TCP port %d'
                    % letsencrypt.PORT)

        if self.noninteractive or one_attempt:
            return False

        if critical:
            return False

        else:
            proceed_option = self.PROCEED_YES
            while proceed_option == self.PROCEED_YES:
                proceed_option = self.ask_proceed_quit('Do you want to try the port again? '
                                                       '(Y / n = next step / q = quit): ')
                if proceed_option == self.PROCEED_NO:
                    return True
                elif proceed_option == self.PROCEED_QUIT:
                    return False

                # Test again
                ok = letsencrypt.test_port_open(ip=ip)
                if self.debug_simulate_vpc:
                    ok = False
                if ok:
                    self.last_le_port_open = True
                    return True
            pass
        pass

    def le_install(self, ejbca):
        self.tprint('\nInstalling LetsEncrypt certificate for: %s' % (', '.join(ejbca.domains)))
        ret = ejbca.le_enroll()
        if ret == 0:
            Core.write_configuration(ejbca.config)
            ejbca.jboss_reload()
            self.tprint('\nPublicly trusted certificate installed (issued by LetsEncrypt)')

        else:
            self.tprint('\nFailed to install publicly trusted certificate, self-signed certificate will be '
                        'used instead, code=%s.' % ret)
            self.tprint('You can try it again later with command renew\n')
        return ret

    def le_renew(self, ejbca):
        le_test = LetsEncrypt(staging=self.args.le_staging)

        renew_needed = self.args.force or le_test.test_certificate_for_renew(domain=ejbca.hostname,
                                                                             renewal_before=60*60*24*20) != 0
        if not renew_needed:
            self.tprint('\nRenewal for %s is not needed now. Run with --force to override this' % ejbca.hostname)
            return 0

        self.tprint('\nRenewing LetsEncrypt certificate for: %s' % ejbca.hostname)
        ret = ejbca.le_renew()
        if ret == 0:
            Core.write_configuration(ejbca.config)
            ejbca.jboss_reload()
            self.tprint('\nNew publicly trusted certificate installed (issued by LetsEncrypt)')

        elif ret == 1:
            self.tprint('\nRenewal not needed, certificate did not change')

        else:
            self.tprint('\nFailed to renew LetsEncrypt certificate, code=%s.' % ret)
            self.tprint('You can try it again later with command renew\n')
        return ret

    def install_check_memory(self, syscfg=None):
        """
        Checks if the system has enough virtual memory to successfully finish the installation.
        If not, it adds a new swap file.

        :param syscfg:
        :return:
        """
        if syscfg is None:
            syscfg = self.syscfg

        if not syscfg.is_enough_ram():
            total_mem = syscfg.get_total_usable_mem()
            self.tprint('\nTotal memory in the system is low: %d MB, installation requires at least 2GB'
                        % int(math.ceil(total_mem/1024.0/1024.0)))

            self.tprint('New swap file will be installed in /var')
            self.tprint('It will take approximately 2 minutes')
            code, swap_name, swap_size = syscfg.create_swap()
            if code == 0:
                self.tprint('\nNew swap file was created %s %d MB and activated'
                            % (swap_name, int(math.ceil(swap_size/1024.0/1024.0))))
            else:
                self.tprint('\nSwap file could not be created. Please, inspect the problem and try again')
                return self.return_code(1)

            # Recheck
            if not syscfg.is_enough_ram():
                self.tprint('Error: still not enough memory. Please, resolve the issue and try again')
                return self.return_code(1)
            self.tprint('')
        return 0

    #
    # Params, misc, main
    #

    def ask_for_email_reason(self, is_required=None):
        if is_required:
            self.tprint('We need your email address for:\n'
                        '   a) identity verification for EnigmaBridge account \n'
                        '   b) LetsEncrypt certificate registration')
            self.tprint('We will send you a verification email.')
            self.tprint('Without a valid e-mail address you won\'t be able to continue with the installation\n')
        else:
            self.tprint('We need your email address for:\n'
                        '   a) identity verification in case of a recovery / support \n'
                        '   b) LetsEncrypt certificate registration')
            self.tprint('It\'s optional but we highly recommend to enter a valid e-mail address'
                        ' (especially on a production system)\n')

    def is_args_le_verification_set(self):
        """True if LetsEncrypt domain verification is set in command line - potential override"""
        return self.args.le_verif is not None

    def get_args_le_verification(self, default=None):
        meth = self.args.le_verif
        if meth is None:
            return default
        if meth == LE_VERIFY_DNS:
            return LE_VERIFY_DNS
        elif meth == LE_VERIFY_TLSSNI:
            return LE_VERIFY_TLSSNI
        else:
            raise ValueError('Unrecognized LetsEncrypt verification method %s' % meth)

    def get_args_vpc(self, default=None):
        is_vpc = self.args.is_vpc
        if is_vpc is None:
            return default
        return is_vpc

    def get_args_intro(self, parser):
        """
        Argument parser intro text
        :return:
        """
        parser.description = 'EnigmaBridge AWS client'

    def check_env(self):
        """
        Checks if the ENV vars are set properly - look for EJBCA_HOME, JBOSS_HOME.
        :return:
        """
        # TODO: for zero-install EJBCA & JBoss will be installed, dont check it here...
        envars = ['EJBCA_HOME', 'JBOSS_HOME']
        for var in envars:
            if var not in os.environ:
                self.tprint(self.t.red('Error') + ': Environment variable missing: %s' % var)
                self.tprint('Please, start the installer with: sudo -E -H')
                return False
        return True

    def init_argparse(self):
        """
        Initializes argument parser object
        :return: parser
        """
        parser = argparse.ArgumentParser()
        self.get_args_intro(parser)

        parser.add_argument('-n', '--non-interactive', dest='noninteractive', action='store_const', const=True,
                            help='non-interactive mode of operation, command line only')
        parser.add_argument('-r', '--attempts', dest='attempts', type=int, default=3,
                            help='number of attempts in non-interactive mode')
        parser.add_argument('-l', '--pid-lock', dest='pidlock', type=int, default=-1,
                            help='number of attempts for pidlock acquire')
        parser.add_argument('--debug', dest='debug', action='store_const', const=True,
                            help='enables debug mode')
        parser.add_argument('--verbose', dest='verbose', action='store_const', const=True,
                            help='enables verbose mode')
        parser.add_argument('--force', dest='force', action='store_const', const=True, default=False,
                            help='forces some action (e.g., certificate renewal)')
        parser.add_argument('--email', dest='email', default=None,
                            help='email address to use instead of prompting for one')

        parser.add_argument('--reg-type', dest='reg_type', default=None,
                            help='Optional user registration type')
        parser.add_argument('--reg-token', dest='reg_token', default=None,
                            help='Optional user registration token')

        parser.add_argument('--env-dev', dest='env_dev', action='store_const', const=True, default=None,
                            help='Use the devel environment in the EnigmaBridge')
        parser.add_argument('--env-test', dest='env_test', action='store_const', const=True, default=None,
                            help='Use the test environment in the EnigmaBridge')

        parser.add_argument('--db-type', dest='db_type', default=None,
                            help='Database type to use (e.g., mysql)')

        parser.add_argument('--vpc', dest='is_vpc', default=None, type=int,
                            help='Sets whether the installation is in Virtual Private Cloud (VPC, public IP is not '
                                 'accessible from the outside - NAT/Firewall). 1 for VPC, 0 for public IP')

        parser.add_argument('--le-verification', dest='le_verif', default=None,
                            help='Preferred LetsEncrypt domain verification method (%s, %s)'
                                 % (LE_VERIFY_TLSSNI, LE_VERIFY_DNS))

        parser.add_argument('--le-staging', dest='le_staging', action='store_const', const=True, default=False,
                            help='Uses staging CA without rate limiting')

        parser.add_argument('--yes', dest='yes', action='store_const', const=True,
                            help='answers yes to the questions in the non-interactive mode, mainly for init')

        parser.add_argument('--allow-update', action='store_const', const=True,
                            help='Inherited option from auto-update wrapper, no action here')
        parser.add_argument('--no-self-upgrade', action='store_const', const=True,
                            help='Inherited option from auto-update wrapper, no action here')
        parser.add_argument('--os-packages-only', action='store_const', const=True,
                            help='Inherited option from auto-update wrapper, no action here')

        parser.add_argument('commands', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='commands to process')
        return parser

    def app_main(self):
        """
        Main entry point for CLI - parsing arguments, setting up environment, starting cmdloop.
        :return:
        """
        # Backup original arguments for later parsing
        args_src = sys.argv
        parser = self.init_argparse()

        self.args, unknown = parser.parse_known_args(args=args_src[1:])
        self.noninteractive = self.args.noninteractive
        for x in unknown:
            logger.debug('Unknown argument: %s' % x)

        if self.args.env_dev is not None and self.args.env_test is not None:
            self.tprint(self.t.red('Error: env-dev and env-test are mutually exclusive'))
            sys.exit(2)

        # Fixing cmd2 arg parsing, call cmdLoop
        sys.argv = [args_src[0]]
        for cmd in self.args.commands:
            sys.argv.append(cmd)

        # Terminate after execution is over on the non-interactive mode
        if self.noninteractive:
            sys.argv.append('quit')

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        # Logging - filter out too verbose Sarge logging messages
        for handler in logging.getLogger().handlers:
            handler.addFilter(util.SargeLogFilter('hnd'))
        logging.getLogger().addFilter(util.SargeLogFilter('root'))

        self.audit.audit_value(key='args', as_dict=self.args)
        self.cmdloop()
        sys.argv = args_src

        # Noninteractive - return the last result from the operation (for scripts)
        if self.noninteractive:
            sys.exit(self.last_result)


def main():
    app = Installer()
    app.app_main()


if __name__ == '__main__':
    main()


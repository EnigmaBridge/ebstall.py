#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

from cmd2 import Cmd
import argparse
import sys
import os
import math
import types
import traceback
from audit import AuditManager
import pid
import time
import util
import errors
import textwrap
import logging
import coloredlogs
from blessed import Terminal
from consts import *
from core import Core
from config import Config, EBSettings
from registration import Registration, InfoLoader
from softhsm import SoftHsmV1Config
from ejbca import Ejbca
from ebsysconfig import SysConfig
from letsencrypt import LetsEncrypt
from ebclient.registration import ENVIRONMENT_PRODUCTION, ENVIRONMENT_DEVELOPMENT, ENVIRONMENT_TEST
from pkg_resources import get_distribution, DistributionNotFound


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.ERROR)


class InstallerBase(Cmd):
    """
    EnigmaBridge CLI installer & software manager base class
    """
    prompt = '$> '

    PIP_NAME = 'ebstall'
    PROCEED_YES = 'yes'
    PROCEED_NO = 'no'
    PROCEED_QUIT = 'quit'

    def __init__(self, *args, **kwargs):
        """
        Init core
        :param args:
        :param kwargs:
        :return:
        """
        Cmd.__init__(self, *args, **kwargs)
        self.core = Core()

        self.args = None
        self.last_result = 0
        self.noninteractive = False

        self.config = None
        self.eb_settings = None
        self.email = None
        self.user_reg_type = None
        self.user_reg_token = None

        self.audit = AuditManager(to_root=True, auto_flush=True, flush_enabled=False)
        self.syscfg = SysConfig(print_output=True, audit=self.audit)

        self.version = self.load_version()
        self.t = Terminal()
        self.audit.audit_value(version=self.version)

    def load_version(self):
        """
        Loads version code of the EnigmaBridge Installer
        :return: version number or 'Trunk' if not detected
        """
        dist = None
        version = None
        try:
            dist = get_distribution(self.PIP_NAME)
            dist_loc = os.path.normcase(dist.location)
            here = os.path.normcase(__file__)
            if not here.startswith(dist_loc):
                raise DistributionNotFound
            else:
                version = dist.version
        except:
            version = 'Trunk'
        return version

    def get_env(self):
        """
        Determines which environment to use.
        Priority from top to bottom:
         - command line switch
         - ENV[ENIGMA_ENV_DEVEL], ENV[ENIGMA_ENV_TEST]
         - /etc/enigma/config.json
         - eb-settings.json
         - default: production
        :return:
        """
        if self.args.env_dev:
            return ENVIRONMENT_DEVELOPMENT
        if self.args.env_test:
            return ENVIRONMENT_TEST
        if 'ENIGMA_ENV_DEVEL' in os.environ:
            return ENVIRONMENT_DEVELOPMENT
        if 'ENIGMA_ENV_TEST' in os.environ:
            return ENVIRONMENT_TEST
        if self.config is not None and self.config.env is not None:
            return self.config.env
        if self.eb_settings is not None and self.eb_settings.env is not None:
            return self.eb_settings.env
        return ENVIRONMENT_PRODUCTION

    #
    # Cli helpers
    #

    def tprint(self, *args, **kwargs):
        """
        Print wrapper - for additional logging & inspection
        :param args:
        :param kwargs:
        :return:
        """
        print(*args, **kwargs)
        self.audit.audit_print(*args, **kwargs)

    def tprint_sensitive(self, *args, **kwargs):
        """
        Print wrapper - for additional logging & inspection
        :param args:
        :param kwargs:
        :return:
        """
        print(*args, **kwargs)
        self.audit.audit_print_sensitive(*args, **kwargs)

    def return_code(self, code=0, if_interactive_return_ok=False):
        """
        Sets return code to the state and returns it as value.
        Used to return return code and save it to the internal state for further processing (e.g., chaining).
        :param code:
        :param if_interactive_return_ok:
        :return:
        """
        self.last_result = code
        if if_interactive_return_ok:
            return 0
        return code

    def cli_separator(self):
        """
        Prints section separator ---
        :return:
        """
        self.tprint('-' * self.get_term_width())

    def cli_sleep(self, iter=5):
        """
        Sleep + newline
        :param iter:
        :return:
        """
        for lines in range(iter):
            self.tprint('')
            time.sleep(0.1)

    def ask_options(self, question=None, allowed_options=None, support_non_interactive=False,
                    non_interactive_return=None):
        """
        Generic asking for choice.
        :param question: question to ask, if None, default is given
        :param allowed_options: iterable of allowed options
        :param support_non_interactive: if False an exception is thrown in non-interactive mode
        :param non_interactive_return: what to return in a non-interactive mode (if allowed)
        :return:
        """
        if allowed_options is None:
            raise ValueError('Invalid allowed options')

        opts = '/'.join(allowed_options)
        question = question if question is not None else ('Please enter your choice (%s): ' % opts)

        if self.noninteractive and not support_non_interactive:
            raise errors.Error('Non-interactive mode not supported for this prompt')

        if self.noninteractive and support_non_interactive:
            self.tprint(non_interactive_return)
            return non_interactive_return

        # Classic interactive prompt
        answer = None
        while answer not in [x.lower() for x in allowed_options]:
            self.audit.audit_input_prompt(question=question)
            answer = util.py_raw_input(question).strip().lower()
            self.audit.audit_input_enter(question=question, answer=answer)
        return answer

    def ask_proceed_quit(self, question=None, support_non_interactive=False,
                         non_interactive_return=PROCEED_YES, quit_enabled=True):
        """
        Ask if user wants to proceed
        :param question:
        :param support_non_interactive:
        :param non_interactive_return:
        :param quit_enabled:
        :return:
        """
        opts = 'Y/n/q' if quit_enabled else 'Y/n'
        question = question if question is not None else ('Do you really want to proceed? (%s): ' % opts)

        if self.noninteractive and not support_non_interactive:
            raise errors.Error('Non-interactive mode not supported for this prompt')

        if self.noninteractive and support_non_interactive:
            if self.args.yes:
                self.tprint(question)
                if non_interactive_return == self.PROCEED_YES:
                    self.tprint('Y')
                elif non_interactive_return == self.PROCEED_NO:
                    self.tprint('n')
                elif non_interactive_return == self.PROCEED_QUIT:
                    self.tprint('q')
                else:
                    raise ValueError('Unknown default value')

                return non_interactive_return
            else:
                raise errors.Error('Non-interactive mode for a prompt without --yes flag')

        # Classic interactive prompt
        confirmation = None
        while confirmation != 'y' and confirmation != 'n' and confirmation != 'q':
            self.audit.audit_input_prompt(question=question)
            confirmation = util.py_raw_input(question).strip().lower()
            self.audit.audit_input_enter(question=question, answer=confirmation)

        if confirmation == 'y':
            return self.PROCEED_YES
        elif confirmation == 'n':
            return self.PROCEED_NO
        else:
            return self.PROCEED_QUIT

    def ask_proceed(self, question=None, support_non_interactive=False, non_interactive_return=True):
        """
        Ask if user wants to proceed
        :param question:
        :param support_non_interactive:
        :param non_interactive_return:
        :return:
        """
        def_return = self.PROCEED_YES if non_interactive_return else self.PROCEED_NO
        ret = self.ask_proceed_quit(question=question,
                                    support_non_interactive=support_non_interactive,
                                    non_interactive_return=def_return,
                                    quit_enabled=False)

        return ret == self.PROCEED_YES

    def ask_for_email_reason(self, is_required=None):
        """
        Prints reason to ask for an email.
        Overridden in particular installer - explaining reasons to user.
        :param is_required:
        :return:
        """

    def is_email_required(self):
        """
        Returns true if the given scenario requires user email
        :return:
        """
        return False

    def ask_for_email(self, is_required=None):
        """
        Asks for Email
        :param is_required:
        :return:
        """
        """Asks user for an email address"""
        confirmation = False
        var = None

        # For different user modes we require an email - validation is performed with it.
        if is_required is None and self.user_reg_type is not None and self.user_reg_type != 'test':
            is_required = True
        if is_required is None:
            is_required = False
        is_required |= self.is_email_required()

        # Take email from the command line
        if self.args.email is not None:
            self.args.email = self.args.email.strip()

            self.tprint('Using email passed as an argument: %s' % self.args.email)
            if len(self.args.email) > 0 and not util.safe_email(self.args.email):
                self.tprint('Email you have entered is invalid, cannot continue')
                raise ValueError('Invalid email address')

            elif is_required and len(self.args.email) == 0:
                self.tprint(self.t.red('Email is required in this mode'))
                raise ValueError('Email is required')

            else:
                return self.args.email

        # Noninteractive mode - use empty email address if got here
        if self.noninteractive:
            if is_required:
                self.tprint(self.t.red('Email address is required to continue with the registration, cannot continue'))
                raise ValueError('Email is required')
            else:
                return ''

        # Explain why we need an email.
        self.ask_for_email_reason(is_required=is_required)

        # Asking for email - interactive
        while not confirmation:
            question = 'Please enter your email address%s: ' % ('' if is_required else ' [empty]')
            self.audit.audit_input_prompt(question=question)
            var = util.py_raw_input(question).strip()
            self.audit.audit_input_enter(question=question, answer=var, sensitive=True)

            question = None
            if len(var) == 0:
                if is_required:
                    self.tprint('Email address is required, cannot be empty')
                    continue
                else:
                    question = 'You have entered an empty email address, is it correct? (Y/n): '
            elif not util.safe_email(var):
                self.tprint('Email you have entered is invalid, try again')
                continue
            else:
                question = 'Is this email correct? \'%s\' (Y/n/q): ' % var
            confirmation = self.ask_proceed_quit(question)
            if confirmation == self.PROCEED_QUIT:
                return self.return_code(1)
            confirmation = confirmation == self.PROCEED_YES

        return var

    def ask_for_token(self):
        """
        Asks for the verification token for the EB user registration
        :return:
        """
        confirmation = False
        var = None

        # Take reg token from the command line
        if self.args.reg_token is not None:
            self.args.reg_token = self.args.reg_token.strip()

            self.tprint('Using registration challenge passed as an argument: %s' % self.args.reg_token)
            if len(self.args.reg_token) > 0:
                self.tprint('Registration challenge is empty')
                raise ValueError('Invalid registration challenge token')

            else:
                return self.args.reg_token

        # Noninteractive mode - use empty email address if got here
        if self.noninteractive:
            raise ValueError('Registration challenge is required')

        # Asking for email - interactive
        while not confirmation:
            question = 'Please enter the challenge: '
            self.audit.audit_input_prompt(question=question)
            var = util.py_raw_input(question).strip()
            self.audit.audit_input_enter(question=question, answer=var, sensitive=True)

            question = None
            if len(var) == 0:
                self.tprint('Registration challenge cannot be empty')
                continue

            else:
                question = 'Is this challenge correct? \'%s\' (Y/n/q): ' % var
            confirmation = self.ask_proceed_quit(question)
            if confirmation == self.PROCEED_QUIT:
                return self.return_code(1)
            confirmation = confirmation == self.PROCEED_YES

        return var

    def get_term_width(self):
        """
        Returns terminal width
        :return: terminal width in characters or 80 if exception encountered
        """
        try:
            width = self.t.width
            if width is None or width <= 0:
                return 80

            return width
        except:
            pass
        return 80

    def wrap_term(self, text="", single_string=False, max_width=None):
        """
        Wraps text to fit the terminal size
        :param text:
        :param single_string:
        :param max_width:
        :return:
        """
        width = self.get_term_width()
        if max_width is not None and width > max_width:
            width = max_width

        res = textwrap.wrap(text, width)
        return res if not single_string else '\n'.join(res)

    def check_root(self):
        """
        Checks if the script was started with root - we need that for file ops :/
        :return:
        """
        uid = os.getuid()
        euid = os.geteuid()
        self.audit.audit_evt('check-root', uid=uid, euid=euid)

        if uid != 0 and euid != 0:
            cmd = ' '.join(sys.argv)
            self.tprint(self.t.red('Error') + ': This action requires root privileges')
            self.tprint('Please, start the installer with: sudo -E -H %s' % cmd)
            return False
        return self.check_env()

    def check_env(self):
        """
        Checks environment variables setup.
        :return:
        """
        return True

    def check_pid(self, retry=True):
        """
        Checks if the tool is running.
        :param retry:
        :return:
        """
        first_retry = True
        attempt_ctr = 0
        while first_retry or retry:
            try:
                first_retry = False
                attempt_ctr += 1

                self.core.pidlock_create()
                if attempt_ctr > 1:
                    self.tprint('\nPID lock acquired')
                return True

            except pid.PidFileAlreadyRunningError as e:
                return True

            except pid.PidFileError as e:
                pidnum = self.core.pidlock_get_pid()
                self.tprint('\nError: CLI already running in exclusive mode by PID: %d' % pidnum)

                if self.args.pidlock >= 0 and attempt_ctr > self.args.pidlock:
                    return False

                self.tprint('Next check will be performed in few seconds. Waiting...')
                time.sleep(3)
        pass

    #
    # Cli commands
    #

    def do_version(self, line):
        self.tprint('%s-%s' % (self.PIP_NAME, self.version))


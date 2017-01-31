from cmd2 import Cmd
import argparse
import sys
import os
import math
import types
import traceback
import pid
import time
import util
import errors
import textwrap
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
from cli import Installer
import logging
import coloredlogs


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

    def init_argparse(self):
        """
        Adding new VPN related arguments
        :return:
        """
        parser = Installer.init_argparse(self)
        return parser

    def ask_for_email_reason(self, is_required=None):
        """
        Reason why we need email - required in VPN case.
        :param is_required:
        :return:
        """
        if is_required:
            self.tprint('We need your email address for:\n'
                        '   a) identity verification for EnigmaBridge account \n'
                        '   b) LetsEncrypt certificate registration'
                        '   c) PKI setup - VPN configuration')
            self.tprint('We will send you a verification email.')
            self.tprint('Without a valid e-mail address you won\'t be able to continue with the installation\n')
        else:
            raise ValueError('Email is required in VPN case')

    def do_init(self, line):
        self.tprint('Going to install VPN server backed by Enigma Bridge FIPS140-2 encryption service.\n')

        # EJBCA installation
        init_res = Installer.do_init(self, line)
        return init_res


def main():
    app = VpnInstaller()
    app.app_main()


if __name__ == '__main__':
    main()


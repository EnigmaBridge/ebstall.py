#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import types
import traceback
import logging
import coloredlogs
from core import Core
from config import Config, EBSettings
from cli import main as main_pki
from clivpn import main as main_vpn
from clivpn import VpnInstaller


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.ERROR)


class CliRouter(object):
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

        # Init state
        self.eb_cfg = None
        self.config = None
        self.args = None

    def init_load_settings(self):
        """
        Loads EB settings as a part of the init. If settings exist already, the backup is performed.
        :return:
        """
        try:
            self.eb_cfg = Core.get_default_eb_config()
            self.config = Core.read_configuration()
        except Exception as e:
            logger.debug('Exception in reading the config: %s' % e)

        return 0

    def init_argparse(self):
        """
        Initializes argument parser object
        :return: parser
        """
        vpn_installer = VpnInstaller()
        parser = vpn_installer.init_argparse()

        parser.add_argument('--mode-pki', dest='mode_pki', action='store_const', const=True,
                            help='PKI only mode')
        parser.add_argument('--mode-privspace', dest='mode_privspace', action='store_const', const=True,
                            help='Private space installer mode')
        parser.add_argument('--mode-installer', dest='mode_installer', default=None,
                            help='Private space installer mode')

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
        install_type = 'vpn'

        # If config is non-empty, use config base installer mode.
        if self.config is not None:
            if self.config.vpn_installed:
                logger.debug('Config base mode: VPN')
                install_type = 'vpn'
            else:
                logger.debug('Config base mode: PKI')
                install_type = 'pki'

        # Command line overrides
        if self.args.mode_installer is not None:
            install_type = self.args.mode_installer
        if self.args.mode_pki:
            install_type = 'pki'
        if self.args.mode_privspace:
            install_type = 'vpn'

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        if install_type == 'pki':
            logger.debug('Choosing PKI mode')
            main_pki()
        elif install_type == 'vpn':
            logger.debug('Choosing VPN mode')
            main_vpn()
        else:
            raise ValueError('Unknown mode')


def main():
    app = CliRouter()
    app.app_main()


if __name__ == '__main__':
    main()


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



    def init_argparse(self):
        """
        Adding new VPN related arguments
        :return:
        """
        parser = Installer.init_argparse(self)
        return parser


def main():
    app = VpnInstaller()
    app.app_main()


if __name__ == '__main__':
    main()


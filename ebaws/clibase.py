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

    PIP_NAME = 'ebins'
    PROCEED_YES = 'yes'
    PROCEED_NO = 'no'
    PROCEED_QUIT = 'quit'


#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import logging
import yaql
from yaql import yaqlization
from yaql.language import specs
from yaql.cli import cli_functions
from yaql.language.factory import OperatorType

from config import Config
from core import Core
from ebstall.ebsysconfig import SysConfig
from ebstall.osutil import PackageInfo, OSInfo
from errors import *
import requests
import util
import re
import errors
import consts
import json
import collections
from audit import AuditManager

from ebstall import versions
from ebstall.tools import versions_yaql


__author__ = 'dusanklinec'


logger = logging.getLogger(__name__)


#
# Updater
#


class Updater(object):
    """
    Updating the private space
    """
    def __init__(self, config=None, audit=None, syscfg=None):
        self.engine = None
        self.root = None
        self.config = config
        self.audit = audit
        self.syscfg = syscfg

    def init_parser(self):
        """
        Initializes yaql parser engine. Builds parsing rules.
        There is usually one engine for the whole application. Heavyweight object.
        :return: 
        """
        factory = yaql.YaqlFactory()
        versions_yaql.register_factory(factory)

        engine_options = {
            'yaql.limitIterators': 100000,
            'yaql.convertSetsToLists': True,
            'yaql.memoryQuota': 1000000
        }

        self.engine = factory.create(options=engine_options)

    def new_context(self):
        """
        Prepares a new context for new evaluation. 
        Context should be new for each eval. Lightweight object.
        :return: 
        """
        ctxt = yaql.create_context()

        # Register all required functions to the context
        versions_yaql.register(ctxt, self.engine)
        return ctxt

    def gen_data(self):
        """
        Generates the root data object for the YAQL evaluation.
        :return: 
        """
        self.root = collections.OrderedDict()
        self.root['config'] = self.config
        self.root['ebstall_version'] = versions.Version(self.config.ebstall_version) if self.config is not None else versions.Version('0')
        self.root['os'] = self.syscfg.get_os()
        self.root['pkgs'] = {x.name: x for x in self.syscfg.get_installed_packages()}

        # Allowing access to methods & attributes
        yaqlization.yaqlize(Config, blacklist=['set_config'])
        yaqlization.yaqlize(OSInfo)
        yaqlization.yaqlize(PackageInfo)

        return self.root

    def eval(self, expr, ctx=None):
        """
        Evaluates an expression
        :param expr: 
        :return: 
        """
        if self.engine is None:
            self.init_parser()

        if ctx is None:
            ctx = self.new_context()

        res = self.engine(expr).evaluate(self.root, ctx)
        return res

if __name__ == "__main__":
    data = {}
    engine_options = {
        'yaql.limitIterators': 1000,
        'yaql.convertSetsToLists': True,
        'yaql.memoryQuota': 100000
    }

    config = None
    syscfg = SysConfig()
    updater = Updater(syscfg=syscfg, config=config)
    updater.init_parser()
    updater.gen_data()

    # CLI hack
    ctx = updater.new_context()
    cli_functions.register_in_context(ctx, updater.engine)
    updater.eval('__main(false)', ctx)




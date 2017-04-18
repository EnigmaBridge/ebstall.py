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
from functools import reduce
import types
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
    def __init__(self, config=None, audit=None, sysconfig=None, ebstall_version=None):
        self.engine = None
        self.root = None
        self.config = config
        self.audit = audit
        self.syscfg = sysconfig
        self.ebstall_version = ebstall_version

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

    def gen_rule_data(self):
        """
        Generates the root data object for the YAQL evaluation.
        :return: 
        """
        self.root = collections.OrderedDict()

        # Config & versions, abbrevs
        self.root['config'] = self.config
        self.root['ebstall_version'] = versions.Version(self.ebstall_version)

        self.root['ebstall_version_initial'] = versions.Version(self.config.ebstall_version_initial) \
            if self.config is not None else versions.Version('0')

        self.root['ebstall_cfg_version'] = versions.Version(self.config.ebstall_version) \
            if self.config is not None else versions.Version('0')

        self.root['install_version'] = versions.Version(self.config.install_version) \
            if self.config is not None else versions.Version('0')

        self.root['source_image_code'] = self.config.source_image_code \
            if self.config is not None else None

        # Current OS info
        self.root['os'] = self.syscfg.get_os()

        # Installed packages
        packages = self.syscfg.get_installed_packages()
        self.root['pkgs'] = {x.name: x for x in packages}
        self.root['pkgs_lst'] = packages
        self.root['pkgs_map'] = {str(x): x for x in packages}

        # Allowing access to methods & attributes
        yaqlization.yaqlize(Config, blacklist=['set_config'])
        yaqlization.yaqlize(OSInfo)
        yaqlization.yaqlize(PackageInfo)

        return self.root

    def eval_single(self, expr, ctx=None):
        """
        Evaluates a single expression
        :param expr: 
        :return: 
        """
        if self.engine is None:
            self.init_parser()

        if ctx is None:
            ctx = self.new_context()

        res = self.engine(expr).evaluate(self.root, ctx)
        return res

    def eval(self, expr, ctx=None, lazy=False):
        """
        Evaluates a single expression / list of expressions
        :param expr: 
        :param ctx: 
        :param lazy: evaluates from the first element, stops if some expression evaluates to None / False
        :return: 
        """
        if isinstance(expr, types.ListType):
            if not lazy:
                return [self.eval_single(x, ctx) for x in expr]

            # Lazy eval
            res = []
            finish_lazy_none = False
            for x in expr:
                if finish_lazy_none:
                    res.append(None)
                    continue

                cur_res = self.eval_single(expr, ctx)
                res.append(cur_res)

                if cur_res is None or not cur_res:
                    finish_lazy_none = True

        else:
            return self.eval_single(expr, ctx)

    def eval_rule(self, rule, ctx=None):
        """
        Evals rule from the update definitions
        Returns a single value
        
        :param rule: 
        :param ctx: 
        :return: 
        """
        res = self.eval(rule, ctx, lazy=True)
        if isinstance(rule, types.ListType):
            return reduce(lambda x, y: x and y, res)
        else:
            return res

    def yaql_cli(self):
        """
        Spawns yaql interactive interface
        (Used for debugging)
        :return: 
        """
        self.init_parser()
        self.gen_rule_data()

        # CLI hack
        ctx = self.new_context()

        def print_output(v, context):
            if context['#nativeOutput']:
                print(v)
            else:
                print(json.dumps(v, indent=4, ensure_ascii=False, cls=util.AutoJSONEncoder))

        cli_functions.print_output = print_output
        cli_functions.register_in_context(ctx, self.engine)
        self.eval('__main(false)', ctx)

    def fetch_update_specs(self, attempts=3):
        """
        Fetched update.json from the provisioning servers
        :return: 
        """

        logger.debug('Going to download update specs from the provisioning servers')
        for provserver in consts.PROVISIONING_SERVERS:
            url = 'https://%s/update/update.json' % provserver

            for attempt in range(attempts):
                try:
                    self.audit.audit_evt('prov-update', url=url)
                    res = requests.get(url=url, timeout=15)
                    res.raise_for_status()
                    js = res.json()

                    self.audit.audit_evt('prov-update', url=url, response=js)
                    return js

                except Exception as e:
                    logger.debug('Exception in fetching update defs from the provisioning server: %s' % e)
                    self.audit.audit_exception(e, process='prov-update')

            return 0

    def update_rule_single(self, rule):
        """
        Processes single update rule
        :param rule: 
        :return: 
        """
        # TODO: implement

    def update_rule(self, rule):
        """
        Processes update rule, recursively
        :param rule: 
        :return: 
        """
        if not isinstance(rule, types.ListType):
            return self.update_rule_single(rule)

        res = []
        for crule in rule:
            cur_res = self.update_rule_single(crule)
            res.append(cur_res)
        return res

    def update(self):
        """
        Main update method.
        Downloads update specs from the provisoning server, processes it...
        :return: 
        """

        specs = self.fetch_update_specs()
        updates = specs['updates']
        res = self.update_rule(updates)
        return res


if __name__ == "__main__":
    syscfg = SysConfig()
    updater = Updater(sysconfig=syscfg, config=None)
    updater.yaql_cli()




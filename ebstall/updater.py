#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import logging
import yaql
from yaql.language import specs
from yaql.cli import cli_functions
from yaql.language.factory import OperatorType

from config import Config
from core import Core
from errors import *
import requests
import util
import re
import errors
import consts
import json
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
    def __init__(self):
        self.engine = None

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


if __name__ == "__main__":
    data = None
    engine_options = {
        'yaql.limitIterators': 1000,
        'yaql.convertSetsToLists': True,
        'yaql.memoryQuota': 100000
    }

    factory = yaql.YaqlFactory()
    versions_yaql.register_factory(factory)
    parser = factory.create(options=engine_options)
    context = yaql.create_context()
    versions_yaql.register(context, parser)
    cli_functions.register_in_context(context, parser)
    parser('__main(false)').evaluate(data, context)




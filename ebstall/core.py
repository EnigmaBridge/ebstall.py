#!/usr/bin/env python
# -*- coding: utf-8 -*-

from config import Config, EBSettings
from consts import *
from ebclient import eb_configuration
import json
import os.path
import util
import pid
from datetime import datetime


class Core(object):
    def __init__(self, *args, **kwargs):
        """Init the core functions"""
        self.pidlock = pid.PidFile(pidname='enigma-cli.pid', piddir='/var/run')
        self.pidlock_created = False

    def pidlock_create(self):
        if not self.pidlock_created:
            self.pidlock.create()
            self.pidlock_created = True

    def pidlock_check(self):
        return self.pidlock.check()

    def pidlock_get_pid(self):
        filename = self.pidlock.filename
        if filename and os.path.isfile(filename):
            try:
                with open(filename, "r") as fh:
                    fh.seek(0)
                    pid = int(fh.read().strip())
                    return pid
            except:
                pass

        return None

    @staticmethod
    def get_config_file_path():
        """Returns basic configuration file"""
        return CONFIG_DIR + '/' + CONFIG_FILE

    @staticmethod
    def config_file_exists():
        conf_name = Core.get_config_file_path()
        return os.path.isfile(conf_name)

    @staticmethod
    def is_configuration_nonempty(config):
        return config is not None and config.has_nonempty_config()

    @staticmethod
    def read_configuration():
        if not Core.config_file_exists():
            return None

        conf_name = Core.get_config_file_path()
        return Config.from_file(conf_name)

    @staticmethod
    def write_configuration(cfg):
        util.make_or_verify_dir(CONFIG_DIR, mode=0o755)

        conf_name = Core.get_config_file_path()
        with os.fdopen(os.open(conf_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as config_file:
            config_file.write('// \n')
            config_file.write('// Config file generated: %s\n' % datetime.now().strftime("%Y-%m-%d %H:%M"))
            config_file.write('// \n')
            config_file.write(cfg.to_string() + "\n\n")
        return conf_name

    @staticmethod
    def backup_configuration(config):
        cur_name = Core.get_config_file_path()
        if os.path.exists(cur_name):
            util.make_or_verify_dir(CONFIG_DIR_OLD, mode=0o644)

            opath, otail = os.path.split(cur_name)
            backup_path = os.path.join(CONFIG_DIR_OLD, otail)

            fhnd, fname = util.unique_file(backup_path, 0o644)
            with fhnd:
                fhnd.write(config.to_string()+"\n")
            return fname

    @staticmethod
    def get_default_eb_config():
        """
        Returns default configuration for the EB client
        :return:
        """
        cfg = eb_configuration.Configuration()
        cfg.endpoint_register = eb_configuration.Endpoint.url('https://hut6.enigmabridge.com:8445')
        return cfg

    @staticmethod
    def set_devel_endpoints(cfg):
        """
        Set test/devel endpoints to the EB configuration
        :return:
        """
        cfg.endpoint_register = eb_configuration.Endpoint.url('https://hut0.enigmabridge.com:8445')
        return cfg

    @staticmethod
    def search_for_settings():
        """Tries to search for settings file"""
        for folder in SETTINGS_FOLDERS:
            cur = os.path.join(folder, SETTINGS_FILE)
            if os.path.exists(cur) and os.path.isfile(cur):
                return cur
        return None

    @staticmethod
    def read_settings(path=None):
        """
        Reads the EB settings if available.
        Returns tuple (settings, path)
        :param path:
        :return:
        """
        if path is None:
            path = Core.search_for_settings()
            if path is None:
                return None, None

        settings = EBSettings.from_file(path)
        return settings, path


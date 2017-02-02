#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import collections
import re
import util
import subprocess


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


CONFIG_LINE_BLANK = 0
CONFIG_LINE_COMMENT = 1
CONFIG_LINE_CMD_COMMENT = 2
CONFIG_LINE_CMD = 3


class ConfigLine(object):
    """
    # One open vpn config line
    """
    def __init__(self, idx=None, raw=None, ltype=None, cmd=None, params=None, comment=None, *args, **kwargs):
        self.idx = idx
        self._raw = raw
        self.ltype = ltype
        self.cmd = cmd
        self.params = params if params is not None else ''
        self.comment = comment if comment is not None else ''

    @property
    def raw(self):
        """
        Builds raw config line
        :return:
        """
        if self.ltype in [CONFIG_LINE_COMMENT, CONFIG_LINE_BLANK]:
            return self._raw

        res = '' if self.ltype == CONFIG_LINE_CMD else ';'
        res += '%s %s %s' % (self.cmd, self.params, self.comment)
        return res

    @raw.setter
    def raw(self, val):
        self._raw = val

    @classmethod
    def build(cls, line, idx=0):
        line = line.strip()
        cl = cls(idx=idx, raw=line)

        if line is None or len(line.strip()) == 0:
            cl.ltype = CONFIG_LINE_BLANK
            return cl

        cmt_match = re.match(r'^\s*#.*', line)
        if cmt_match is not None:
            cl.ltype = CONFIG_LINE_COMMENT
            return cl

        cmd_cmt_match = re.match(r'^\s*;.*', line)
        cmd_match = re.match(r'^\s*(;)?\s*([a-zA-Z0-9\-_]+)\s+(.+?)(\s*(#|;).+)?$', line)

        if cmd_match is None and cmd_cmt_match is not None:
            cl.ltype = CONFIG_LINE_COMMENT
            return cl

        cl.ltype = CONFIG_LINE_CMD if cmd_match.group(1) is None else CONFIG_LINE_CMD_COMMENT
        cl.cmd = cmd_match.group(2).strip()
        cl.params = cmd_match.group(3).strip()
        cl.comment = cmd_match.group(4).strip()
        return cl


class OpenVpn(object):
    """
    OpenVPN server configuration & management
    """

    SETTINGS_DIR = '/etc/openvpn'
    SETTINGS_FILE = 'server.conf'

    def __init__(self, sysconfig=None, *args, **kwargs):
        self.sysconfig = sysconfig

        # Result of load_config_file_lines
        self.server_config_data = None
        self.server_config_modified = False

    #
    # server.conf reading & modification
    #

    def get_config_file_path(self):
        """
        Returns config file path
        :return: server config file path
        """
        return os.path.join(self.SETTINGS_DIR, self.SETTINGS_FILE)

    def load_config_file_lines(self):
        """
        Loads config file to a string
        :return: array of ConfigLine or None if file does not exist
        """
        cpath = self.get_config_file_path()
        if not os.path.exists(cpath):
            return []

        lines = []
        with open(cpath, 'r') as fh:
            for idx, line in enumerate(fh):
                ln = ConfigLine.build(line=line, idx=idx)
                lines.append(ln)
        return lines

    def set_config_value(self, cmd, value):
        """
        Sets command to the specified value in the configuration file.
        Modifies self.server_config_data, self.server_config_modified
        :param cmd:
        :param value:
        :return: True if file was modified
        """
        # If file is not loaded - load
        if self.server_config_data is None:
            self.server_config_data = self.load_config_file_lines()

        last_cmd_idx = 0
        cmd_set = False

        for idx, cfg in enumerate(self.server_config_data):
            if cfg.ltype not in [CONFIG_LINE_CMD, CONFIG_LINE_CMD_COMMENT]:
                continue
            if cfg.cmd != cmd:
                continue

            last_cmd_idx = idx
            if cfg.params == value:
                if cfg.ltype == CONFIG_LINE_CMD:
                    # Command is already set to the same value. File not modified.
                    return False
                else:
                    # Just change the type to active value - switch from comment to command
                    # Cannot quit yet, has to comment out other values
                    cfg.ltype = CONFIG_LINE_CMD
                    cmd_set = True

            elif cfg.ltype == CONFIG_LINE_CMD:  # same command, but different value - comment this out
                cfg.ltype = CONFIG_LINE_CMD_COMMENT

        if cmd_set:
            self.server_config_modified = True
            return True

        # Command was not set in the existing config file - add new.
        cl = ConfigLine(idx=None, raw=None, ltype=CONFIG_LINE_CMD, cmd=cmd, params=value)
        self.server_config_data.insert(last_cmd_idx+1, cl)
        self.server_config_modified = True
        return True

    def update_config_file(self, force=False):
        """
        Updates server configuration file
        :return: True if file was modified
        """
        if not force and not self.server_config_modified:
            return False

        cpath = self.get_config_file_path()
        fh, backup = util.safe_create_with_backup(cpath, 'w', 0o644)
        with fh:
            for cl in self.server_config_data:
                fh.write(cl.raw + '\n')

        self.server_config_modified = False  # reset after flush
        return True

    #
    # Configuration
    #
    def generate_dh_group(self):
        """
        Generates a new Diffie-Hellman group for the server.
        openssl dhparam -out dh2048.pem 2048
        :return:
        """
        size = 2048  # constant for now
        dh_file = os.path.join(self.SETTINGS_DIR, 'dh%d.pem' % size)
        cmd = 'sudo openssl dhparam -out \'%s\' %d' % (dh_file, size)
        p = subprocess.Popen(cmd, shell=True)
        return p.wait()

    def configure_crl(self, crl_path):
        """
        Configures server with the given CRL file
        :param crl_path:
        :return: True if file was changed
        """
        self.set_config_value('crl-verify', crl_path)
        return self.update_config_file()

    def configure_server(self):
        """
        Perform base server configuration.
        :return: True if file was changed
        """
        self.set_config_value('port', '1194')
        self.set_config_value('proto', 'udp')
        self.set_config_value('cipher', 'AES-256-CBC')
        self.set_config_value('dh', 'dh2048.pem')
        self.set_config_value('ca', 'ca.crt')
        self.set_config_value('cert', 'server.crt')
        self.set_config_value('key', 'server.key')
        return self.update_config_file()




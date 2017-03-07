#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import collections
import re
import util
import subprocess
import types
import osutil
import shutil
import pkg_resources


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


CONFIG_LINE_BLANK = 0
CONFIG_LINE_COMMENT = 1
CONFIG_LINE_CMD_COMMENT = 2
CONFIG_LINE_CMD = 3


class ConfigLine(object):
    """
    One configuration line
    """
    def __init__(self, idx=None, raw=None, ltype=None, cmd=None, params=None, comment=None, *args, **kwargs):
        self.idx = idx
        self._raw = raw
        self.ltype = ltype
        self.cmd = cmd
        self.params = params
        self.comment = comment

    def __repr__(self):
        return 'ConfigLine(idx=%r, ltype=%r, cmd=%r, params=%r, comment=%r, raw=%r)' \
               % (self.idx, self.ltype, self.cmd, self.params, self.comment, self._raw)

    def __str__(self):
        return self.raw

    @property
    def raw(self):
        """
        Builds raw config line
        :return:
        """
        if self.ltype in [CONFIG_LINE_COMMENT, CONFIG_LINE_BLANK]:
            return util.defval(self._raw, '')

        res = '' if self.ltype == CONFIG_LINE_CMD else ';'
        res += '%s = %s %s' % (util.defval(self.cmd, ''), util.defval(self.params, ''), util.defval(self.comment, ''))
        return res.strip()

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

        cmd_match = re.match(r'^\s*(#)?\s*([a-zA-Z0-9\-_.]+)\s*=\s*(.+?)(\s*#.+)??$', line)
        cmt_match = re.match(r'^\s*#.*', line)

        if cmd_match is None and cmt_match is not None:
            cl.ltype = CONFIG_LINE_COMMENT
            return cl

        if cmd_match is None:
            logger.debug('Unrecognized config line: %s' % line)
            cl.ltype = CONFIG_LINE_COMMENT
            return cl

        cl.ltype = CONFIG_LINE_CMD if cmd_match.group(1) is None else CONFIG_LINE_CMD_COMMENT
        cl.cmd = util.strip(cmd_match.group(2))
        cl.params = util.strip(cmd_match.group(3))
        cl.comment = util.strip(cmd_match.group(4))
        return cl


class SysctlConfig(object):
    """
    Parses sysctl-like configuration, allows to modify the configuration and save changes back to the file.
    """

    def __init__(self, config_path=None, static_config=None, *args, **kwargs):
        self.config_path = config_path
        self.static_config = static_config
        self.config_data = None
        self.config_modified = False

    def load(self):
        """
        Loads the config file
        :return:
        """
        self.config_data = self.load_config_file_lines()

    def load_config_file_lines(self):
        """
        Loads config file to a string
        :return: array of ConfigLine or None if file does not exist
        """
        config = []
        lines = []

        cpath = self.config_path
        if cpath is None or not os.path.exists(cpath):
            bare = self.static_config
            lines = [x.strip() for x in bare.split('\n')]

        else:
            with open(cpath, 'r') as fh:
                for line in fh:
                    lines.append(line.strip())

        for idx, line in enumerate(lines):
            ln = ConfigLine.build(line=line, idx=idx)
            config.append(ln)

        return config

    def set_config_value(self, cmd, values=None, remove=False, under_directive=None):
        """
        Sets command to the specified value in the configuration file.
        Loads file from the disk if server_config_data is None (file was not yet loaded).


        Modifies self.config_data, self.config_modified
        :param cmd:
        :param values: single value or array of values for multi-commands (e.g., push).
                       None & remove -> remove all commands. Otherwise just commands with the given values are removed.
        :param remove: if True, configuration command is removed
        :param under_directive: if specified, command is placed under specified directive, if exists
        :return: True if file was modified
        """
        # If file is not loaded - load
        if self.config_data is None:
            self.config_data = self.load_config_file_lines()

        # default position - end of the config file
        last_cmd_idx = len(self.config_data) - 1
        file_changed = False

        values_set = False
        for idx, cfg in enumerate(self.config_data):
            if cfg.ltype not in [CONFIG_LINE_CMD, CONFIG_LINE_CMD_COMMENT]:
                continue

            if under_directive is not None and util.equals_any(cfg.cmd, under_directive):
                last_cmd_idx = idx

            if cfg.cmd != cmd:
                continue

            # Only commands of interest here
            last_cmd_idx = idx
            is_desired_value = cfg.params == values
            is_desired_value |= remove and values is None
            is_desired_value |= not remove and values is None and util.is_empty(cfg.params)
            value_idx = 0 if not remove and cfg.params == values else None

            if is_desired_value:
                if cfg.ltype == CONFIG_LINE_CMD and not remove:
                    # Command is already set to the same value. File not modified.
                    # Cannot quit yet, has to comment out other values
                    if value_idx is not None:
                        if not values_set:
                            values_set = True
                        else:
                            cfg.ltype = CONFIG_LINE_CMD_COMMENT
                            file_changed = True
                    pass

                elif cfg.ltype == CONFIG_LINE_CMD:
                    # Remove command - comment out
                    cfg.ltype = CONFIG_LINE_CMD_COMMENT
                    file_changed = True

                elif cfg.ltype == CONFIG_LINE_CMD_COMMENT and remove:
                    # Remove && comment - leave as it is
                    # Cannot quit yet, has to comment out other values
                    pass

                else:
                    # CONFIG_LINE_CMD_COMMENT and not remove.
                    # Just change the type to active value - switch from comment to command
                    # Cannot quit yet, has to comment out other values
                    do_change = True
                    if value_idx is not None:
                        if not values_set:
                            values_set = True
                        else:
                            do_change = False

                    if do_change:
                        cfg.ltype = CONFIG_LINE_CMD
                        file_changed = True

            elif cfg.ltype == CONFIG_LINE_CMD and not remove:
                # Same command, but different value - comment this out
                # If remove is True, only desired values were removed.
                cfg.ltype = CONFIG_LINE_CMD_COMMENT
                file_changed = True

        if remove:
            self.config_modified |= file_changed
            return file_changed

        # Add those commands not set in the cycle above
        if not values_set:
            cl = ConfigLine(idx=None, raw=None, ltype=CONFIG_LINE_CMD, cmd=cmd, params=values)
            self.config_data.insert(last_cmd_idx + 1, cl)
            file_changed = True

        self.config_modified |= file_changed
        return file_changed

    def dump(self):
        """
        Dumps config to the string
        :return:
        """
        data = []
        for cl in self.config_data:
            data.append(cl.raw)
        return '\n'.join(data)

    def update_config_file(self, force=False):
        """
        Updates server configuration file.
        Resets server_config_modified after the file update was flushed to the disk

        :return: True if file was modified
        """
        if not force and not self.config_modified:
            return False

        fh, backup = util.safe_create_with_backup(self.config_path, 'w', 0o644)
        with fh:
            for cl in self.config_data:
                fh.write(cl.raw + '\n')

        self.config_modified = False  # reset after flush
        return True

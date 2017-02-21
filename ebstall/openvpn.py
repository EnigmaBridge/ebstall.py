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
    # One open vpn config line
    """
    def __init__(self, idx=None, raw=None, ltype=None, cmd=None, params=None, comment=None, *args, **kwargs):
        self.idx = idx
        self._raw = raw
        self.ltype = ltype
        self.cmd = cmd
        self.params = params
        self.comment = comment

    @property
    def raw(self):
        """
        Builds raw config line
        :return:
        """
        if self.ltype in [CONFIG_LINE_COMMENT, CONFIG_LINE_BLANK]:
            return util.defval(self._raw, '')

        res = '' if self.ltype == CONFIG_LINE_CMD else ';'
        res += '%s %s %s' % (util.defval(self.cmd, ''), util.defval(self.params, ''), util.defval(self.comment, ''))
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

        cmt_match = re.match(r'^\s*#.*', line)
        if cmt_match is not None:
            cl.ltype = CONFIG_LINE_COMMENT
            return cl

        cmd_cmt_match = re.match(r'^\s*;.*', line)
        cmd_match = re.match(r'^\s*(;)?\s*([a-zA-Z0-9\-_]+)(\s+.+)?(\s*(#|;).+)?$', line)

        if cmd_match is None and cmd_cmt_match is None:
            logger.debug('VPN unrecognized config line: %s' % line)
            cl.ltype = CONFIG_LINE_COMMENT
            return cl

        if cmd_match is None and cmd_cmt_match is not None:
            cl.ltype = CONFIG_LINE_COMMENT
            return cl

        cl.ltype = CONFIG_LINE_CMD if cmd_match.group(1) is None else CONFIG_LINE_CMD_COMMENT
        cl.cmd = util.strip(cmd_match.group(2))
        cl.params = util.strip(cmd_match.group(3))
        cl.comment = util.strip(cmd_match.group(4))
        return cl


class OpenVpn(object):
    """
    OpenVPN server configuration & management
    """

    SETTINGS_DIR = '/etc/openvpn'
    SETTINGS_FILE = 'server.conf'
    PORT_NUM = 1194
    PORT_TCP = False

    def __init__(self, sysconfig=None, audit=None, write_dots=False, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dost = write_dots

        # Result of load_config_file_lines
        self.server_config_data = None
        self.server_config_modified = False

    #
    # Settings
    #
    def get_ip_net(self):
        """
        Network address for the VPN server
        :return:
        """
        return '10.8.0.0'

    def get_ip_vpn_server(self):
        """
        Returns IP address of the VPN server for clients on the VPN
        :return:
        """
        return '10.8.0.1'

    def get_ip_net_size(self):
        """
        returns network size of the network allocated for OpenVPN
        :return:
        """
        return 24

    def get_ip_mask(self):
        """
        Returns the mask of the network used by OpenVPN
        :return:
        """
        util.net_size_to_mask(self.get_ip_net_size())

    def get_port(self):
        """
        Returns port to use for OpenVPN
        :return: (port, tcp)
        """
        return self.PORT_NUM, self.PORT_TCP

    #
    # server.conf reading & modification
    #
    def get_config_dir(self):
        return self.SETTINGS_DIR

    def get_config_dir_subfile(self, filename):
        return os.path.join(self.get_config_dir(), filename)

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
        config = []
        lines = []

        cpath = self.get_config_file_path()
        if not os.path.exists(cpath):
            bare = self.load_static_config()
            lines = [x.strip() for x in bare.split('\n')]

        else:
            with open(cpath, 'r') as fh:
                for line in fh:
                    lines.append(line.strip())

        for idx, line in enumerate(lines):
            ln = ConfigLine.build(line=line, idx=idx)
            config.append(ln)

        return config

    def load_static_config(self):
        """
        Loads static config from the package
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('consts', 'ovpn-server.conf'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def set_config_value(self, cmd, values, remove=False, under_directive=None):
        """
        Sets command to the specified value in the configuration file.
        Loads file from the disk if server_config_data is None (file was not yet loaded).

        Supports also multicommands - one command with more values.

        Modifies self.server_config_data, self.server_config_modified
        :param cmd:
        :param values: single value or array of values for multi-commands (e.g., push).
                       None & remove -> remove all commands. Otherwise just commands with the given values are removed.
        :param remove: if True, configuration command is removed
        :param under_directive: if specified, command is placed under specified directive, if exists
        :return: True if file was modified
        """
        # If file is not loaded - load
        if self.server_config_data is None:
            self.server_config_data = self.load_config_file_lines()

        # default position - end of the config file
        last_cmd_idx = len(self.server_config_data)-1
        file_changed = False
        if not isinstance(values, types.ListType):
            if values is None:
                values = []
            else:
                values = [values]

        values_set = [False] * len(values)
        for idx, cfg in enumerate(self.server_config_data):
            if cfg.ltype not in [CONFIG_LINE_CMD, CONFIG_LINE_CMD_COMMENT]:
                continue

            if under_directive is not None and util.equals_any(cfg.cmd, under_directive):
                last_cmd_idx = idx

            if cfg.cmd != cmd:
                continue

            # Only commands of interest here
            last_cmd_idx = idx
            is_desired_value = cfg.params in values
            is_desired_value |= remove and len(values) == 0
            value_idx = values.index(cfg.params) if not remove and cfg.params in values else None

            if is_desired_value:
                if cfg.ltype == CONFIG_LINE_CMD and not remove:
                    # Command is already set to the same value. File not modified.
                    # Cannot quit yet, has to comment out other values
                    if value_idx is not None:
                        values_set[value_idx] = True
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
                    cfg.ltype = CONFIG_LINE_CMD
                    file_changed = True
                    if value_idx is not None:
                        values_set[value_idx] = True

            elif cfg.ltype == CONFIG_LINE_CMD and not remove:
                # Same command, but different value - comment this out
                # If remove is True, only desired values were removed.
                cfg.ltype = CONFIG_LINE_CMD_COMMENT
                file_changed = True

        if remove:
            self.server_config_modified = file_changed
            return file_changed

        # Add those commands not set in the cycle above
        ctr = 0
        for idx, cval in enumerate(values):
            if values_set[idx]:
                continue

            cl = ConfigLine(idx=None, raw=None, ltype=CONFIG_LINE_CMD, cmd=cmd, params=cval)
            self.server_config_data.insert(last_cmd_idx+1+ctr, cl)

            ctr += 1
            file_changed = True

        self.server_config_modified = file_changed
        return file_changed

    def update_config_file(self, force=False):
        """
        Updates server configuration file.
        Resets server_config_modified after the file update was flushed to the disk

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
        return self.sysconfig.exec_shell(cmd, write_dots=self.write_dost)

    def configure_crl(self, crl_path):
        """
        Configures server with the given CRL file
        :param crl_path:
        :return: True if file was changed
        """
        self.set_config_value('crl-verify', crl_path, remove=crl_path is None, under_directive='key')
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

        self.set_config_value('user', 'nobody')
        self.set_config_value('group', 'nobody')
        self.set_config_value('server', '%s %s' % (self.get_ip_net(), self.get_ip_mask()))

        # '"dhcp-option DNS 8.8.4.4"',
        # '"dhcp-option DNS 8.8.8.8"',
        push_values = ['"dhcp-option DNS %s"' % self.get_ip_vpn_server(),
                       '"redirect-gateway def1 bypass-dhcp"']
        self.set_config_value('push', push_values)

        return self.update_config_file()

    def store_server_cert(self, ca, cert, key):
        """
        Stores CA, Cert, Key to the storage and fixes permissions
        :return:
        """
        shutil.copy(ca, self.get_config_dir_subfile('ca.crt'))
        shutil.copy(cert, self.get_config_dir_subfile('server.crt'))

        # Key is tricky - do not expose the raw key
        key_file = self.get_config_dir_subfile('server.key')
        if os.path.exists(key_file):
            os.remove(key_file)  # just UX remove, not security sensitive

        # Create file with correct permissions set
        fh = util.safe_open(key_file, 'w', chmod=0o600)
        fh.close()

        ret = self.sysconfig.exec_shell('sudo chown root:root \'%s\'' % key_file, shell=True, write_dots=self.write_dost)
        if ret != 0:
            return ret

        cmd_exec = 'sudo cat \'%s\' >> \'%s\'' % (key, key_file)
        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dost)

    #
    # Installation
    #
    def install(self):
        """
        Installs itself
        :return: installer return code
        """
        cmd_exec = 'sudo yum install -y openvpn'
        if self.sysconfig.get_packager() == osutil.PKG_APT:
            cmd_exec = 'sudo apt-get install -y openvpn'

        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dost)

    def get_svc_map(self):
        """
        Returns service naming for different start systems
        :return:
        """
        return {
            osutil.START_SYSTEMD: 'openvpn.service',
            osutil.START_INITD: 'openvpn'
        }

    def enable(self):
        """
        Enables service after OS start
        :return:
        """
        return self.sysconfig.enable_svc(self.get_svc_map())

    def switch(self, start=None, stop=None, restart=None):
        """
        Starts/stops/restarts the service
        :param start:
        :param stop:
        :param restart:
        :return:
        """
        return self.sysconfig.switch_svc(self.get_svc_map(), start=start, stop=stop, restart=restart)

    def setup_os(self):
        """
        Configures OS
        Enables packet forwarding, sets up the masquerade
        :return:
        """
        # Enable packet forwarding
        ret = self.sysconfig.packet_forwarding()
        if ret != 0:
            return ret

        # Set the masquerade
        ret = self.sysconfig.masquerade(self.get_ip_net(), self.get_ip_net_size())
        if ret != 0:
            return ret

        # Allow port on the firewall
        port, tcp = self.get_port()
        ret = self.sysconfig.allow_port(port=port, tcp=tcp)
        return ret


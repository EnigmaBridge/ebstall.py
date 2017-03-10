#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import logging
import errors
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
    def __init__(self, idx=None, raw=None, ltype=None, cmd=None, params=None, comment=None, paired=False, *args, **kwargs):
        self.idx = idx
        self._raw = raw
        self.ltype = ltype
        self.cmd = cmd
        self.params = params
        self.comment = comment
        self.paired = paired

    def __repr__(self):
        return 'ConfigLine(idx=%r, ltype=%r, cmd=%r, params=%r, comment=%r, raw=%r, paired=%r)' \
               % (self.idx, self.ltype, self.cmd, self.params, self.comment, self._raw, self.paired)

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

        if self.paired:
            res = ['<%s>' % self.cmd, self.params, '</%s>' % self.cmd]
            if self.ltype == CONFIG_LINE_CMD_COMMENT:
                return ';' + (''.join(res)).strip()
            return ('\n'.join(res)).strip()

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
        cmd_match = re.match(r'^\s*(;)?\s*([a-zA-Z0-9\-_]+)(\s+.+?)?(\s*(#|;).+)??$', line)
        cmd_pair = re.match(r'^\s*(;)?\s*<([a-zA-Z0-9\-_]+)>(\s+.+?)?</([a-zA-Z0-9\-_]+)>$', line, re.MULTILINE | re.DOTALL)

        if cmd_pair:
            cl.ltype = CONFIG_LINE_CMD if cmd_pair.group(1) is None else CONFIG_LINE_CMD_COMMENT
            open_tag = cmd_pair.group(2)
            data_tag = cmd_pair.group(3)
            close_tag = cmd_pair.group(4)

            if open_tag != close_tag:
                raise ValueError('Open tag does not equal close tag')
            cl.cmd = open_tag
            cl.params = data_tag.strip()
            cl.paired = True
            return cl

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


class OpenVpnConfig(object):
    """
    Parses OpenVPN configuration, allows to modify the configuration and save changes back to the file.
    """

    def __init__(self, config_path=None, static_config=None, audit=None, *args, **kwargs):
        self.config_path = config_path
        self.static_config = static_config
        self.config_data = None
        self.config_modified = False
        self.audit = audit

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
            self.audit.audit_file_read(cpath)

        # Parsing config file line by line, with support for paired config tags, e.g., <ca>ABF...</ca>
        # Paired tags can be multiline, in that case we consider it as one string, with \n characters.
        paired_tag = None
        paired_buff = []
        for idx, line in enumerate(lines):
            cline = line.strip()

            # Opened paired tag. Either find a closing tag or add line to the buffer and continue with reading.
            if paired_tag is not None:
                end_tag = '</%s>' % paired_tag
                paired_buff.append(line)

                if end_tag in cline and not cline.endswith(end_tag):
                    raise ValueError('Parse error, closing tag is on the same line, but not the last element')
                elif end_tag in cline:
                    ln = ConfigLine.build(line='\n'.join(paired_buff), idx=idx)
                    config.append(ln)
                    paired_tag = None
                continue

            # Check for opening tag
            pair_match = re.match(r'^\s*(;)?\s*<([a-zA-Z0-9\-_]+)>(\s+.+?)?$', cline)
            if pair_match is not None:
                if paired_tag is not None:
                    raise ValueError('Parse error, unclosed previously opened tag: %s' % paired_tag)

                paired_buff = [line]
                paired_tag = pair_match.group(2)
                end_tag = '</%s>' % paired_tag
                tail = pair_match.group(3)

                if tail is not None and end_tag in tail and not tail.endswith(end_tag):
                    raise ValueError('Parse error, closing tag is on the same line, but not the last element')
                if tail is not None and end_tag in tail:
                    ln = ConfigLine.build(line=line, idx=idx)
                    config.append(ln)
                    paired_tag = None
                    continue

            if paired_tag is not None:
                continue

            # Normal one-line directive
            ln = ConfigLine.build(line=line, idx=idx)
            config.append(ln)

        if paired_tag is not None:
            raise ValueError('Parsing error, unclosed paired tag %s' % paired_tag)

        return config

    def set_config_value(self, cmd, values=None, remove=False, under_directive=None):
        """
        Sets command to the specified value in the configuration file.
        Loads file from the disk if server_config_data is None (file was not yet loaded).

        Supports also multicommands - one command with more values.

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
        single_directive = False  # no parameter given

        if values is None:
            single_directive = True
            values = [None]

        if not isinstance(values, types.ListType):
            values = [values]

        values_set = [False] * len(values)
        for idx, cfg in enumerate(self.config_data):
            if cfg.ltype not in [CONFIG_LINE_CMD, CONFIG_LINE_CMD_COMMENT]:
                continue

            if under_directive is not None and util.equals_any(cfg.cmd, under_directive):
                last_cmd_idx = idx

            if cfg.cmd != cmd:
                continue

            # Only commands of interest here
            last_cmd_idx = idx
            is_desired_value = cfg.params in values
            is_desired_value |= remove and (util.is_empty(values) or single_directive)
            is_desired_value |= not remove and (util.is_empty(values) or single_directive) and util.is_empty(cfg.params)
            value_idx = values.index(cfg.params) if not remove and cfg.params in values else None

            if is_desired_value:
                if cfg.ltype == CONFIG_LINE_CMD and not remove:
                    # Command is already set to the same value. File not modified.
                    # Cannot quit yet, has to comment out other values
                    if value_idx is not None:
                        if not values_set[value_idx]:
                            values_set[value_idx] = True
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
                        if not values_set[value_idx]:
                            values_set[value_idx] = True
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
        ctr = 0
        for idx, cval in enumerate(values):
            if values_set[idx]:
                continue

            cl = ConfigLine(idx=None, raw=None, ltype=CONFIG_LINE_CMD, cmd=cmd, params=cval)
            self.config_data.insert(last_cmd_idx + 1 + ctr, cl)

            ctr += 1
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

        fh, backup = util.safe_create_with_backup(self.config_path, mode='w', chmod=0o644, backup_suffix='.backup')
        with fh:
            for cl in self.config_data:
                fh.write(cl.raw + '\n')
            self.audit.audit_file_write(self.config_path)

        self.config_modified = False  # reset after flush
        return True


class OpenVpn(object):
    """
    OpenVPN server configuration & management
    """

    SETTINGS_DIR = '/etc/openvpn'
    SETTINGS_FILE = 'server.conf'
    PORT_NUM = 1194
    PORT_TCP = True

    def __init__(self, sysconfig=None, audit=None, write_dots=False, client_config_path=None, *args, **kwargs):
        self.sysconfig = sysconfig
        self.write_dost = write_dots
        self.audit = audit

        # Result of load_config_file_lines
        self.server_config = None
        self.client_config = None
        self.client_config_path = client_config_path

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
        return util.net_size_to_mask(self.get_ip_net_size())

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

    def load_static_config(self):
        """
        Loads static config from the package
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('consts', 'ovpn-server.conf'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def init_server_config(self):
        """
        Initializes server configuration parser
        :return:
        """
        if self.server_config is None:
            self.server_config = OpenVpnConfig(config_path=self.get_config_file_path(),
                                               static_config=self.load_static_config(),
                                               audit=self.audit)

    def init_client_config(self):
        """
        Client configuration parser
        :return:
        """
        if self.client_config_path is None:
            logger.debug('Client configuration path not provided')
            return

        if not os.path.exists(self.client_config_path):
            raise errors.SetupError('Could not find client VPN configuration file: %s' % self.client_config_path)

        if self.client_config is None:
            self.client_config = OpenVpnConfig(config_path=self.client_config_path, audit=self.audit)


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
        self.init_server_config()
        self.server_config.set_config_value('crl-verify', crl_path, remove=crl_path is None, under_directive='key')
        return self.server_config.update_config_file()

    def configure_server(self):
        """
        Perform base server configuration.
        :return: True if file was changed
        """
        port, tcp = self.get_port()
        self.init_server_config()
        self.server_config.set_config_value('port', '%s' % port)
        self.server_config.set_config_value('proto', 'udp' if not tcp else 'tcp')
        self.server_config.set_config_value('server', '%s %s' % (self.get_ip_net(), self.get_ip_mask()))

        self.server_config.set_config_value('dh', 'dh2048.pem')
        self.server_config.set_config_value('ca', 'ca.crt')
        self.server_config.set_config_value('cert', 'server.crt')
        self.server_config.set_config_value('key', 'server.key')

        self.server_config.set_config_value('client-to-client')
        self.server_config.set_config_value('persist-tun', remove=True)
        self.server_config.set_config_value('comp-lzo', remove=True)
        self.server_config.set_config_value('keepalive', '2 20')
        self.server_config.set_config_value('topology', 'subnet')
        self.server_config.set_config_value('sndbuf', '0')
        self.server_config.set_config_value('rcvbuf', '0')

        # Protocol dependent
        if tcp:
            self.server_config.set_config_value('replay-window', remove=True)
        else:
            self.server_config.set_config_value('replay-window', '2048')

        self.server_config.set_config_value('cipher', 'AES-256-CBC')
        self.server_config.set_config_value('auth', 'SHA256')

        # This can be enabled after certificates are generated with exact usage.
        # self.server_config.set_config_value('remote-cert-tls', 'server')

        self.server_config.set_config_value('user', 'nobody')
        self.server_config.set_config_value('group', 'nobody')

        # Use internal DNS to prevent DNS leaks
        push_values = ['"dhcp-option DNS %s"' % self.get_ip_vpn_server(),
                       '"redirect-gateway def1 bypass-dhcp"',
                       '"sndbuf 393216"',
                       '"rcvbuf 393216"']
        self.server_config.set_config_value('push', push_values)

        return self.server_config.update_config_file()

    def configure_client(self):
        """
        Configures client VPN file
        :return:
        """
        self.init_client_config()
        if self.client_config is None:
            logger.debug('Could not configure client - no config object')
            return

        port, tcp = self.get_port()
        self.client_config.set_config_value('proto', 'udp' if not tcp else 'tcp')
        self.client_config.set_config_value('cipher', 'AES-256-CBC')
        self.client_config.set_config_value('auth', 'SHA256')
        self.client_config.set_config_value('persist-tun', remove=True)
        self.client_config.set_config_value('keepalive', '2 20')
        self.client_config.set_config_value('comp-lzo', remove=True)
        self.client_config.set_config_value('block-outside-dns')

        # Protocol dependent
        if tcp:
            self.client_config.set_config_value('replay-window', remove=True)
        else:
            self.client_config.set_config_value('replay-window', '2048')

        return self.client_config.update_config_file()

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


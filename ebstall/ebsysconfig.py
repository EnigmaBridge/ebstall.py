#!/usr/bin/env python
# -*- coding: utf-8 -*-

from past.builtins import basestring
import os

import ebstall.osutil
import util
from sarge import run, Capture, Feeder
from ebclient.eb_utils import EBUtils
from datetime import datetime
import time
import sys
import types
import subprocess
import shutil
import re
import psutil
import math
import consts
import osutil
from audit import AuditManager
import logging
import traceback
import pkg_resources


__author__ = 'dusanklinec'
logger = logging.getLogger(__name__)


FIREWALL_IPTABLES = 'iptables'
FIREWALL_FIREWALLD = 'firewalld'
FIREWALL_UFW = 'ufw'
FIREWALLS = [FIREWALL_FIREWALLD, FIREWALL_UFW, FIREWALL_IPTABLES]


class SysConfig(object):
    """Basic system configuration object"""
    SYSCONFIG_BACKUP = '/root/ebstall.backup'

    REGEX_IPTABLES_POSTROUTING = re.compile(r'.*?(?:^|\b|\s)-A\s+POSTROUTING(?:$|\b|\s).*')
    REGEX_IPTABLES_MASQUERADE = re.compile(r'.*?(?:^|\b|\s)-j\s+MASQUERADE(?:$|\b|\s).*')
    REGEX_IPTABLES_SRC = r'.*?(?:^|\b|\s)-s\s+%s(?:$|\b|\s).*'
    REGEX_IPTABLES_OUTPUT_DEV = re.compile(r'.*?(?:^|\b|\s)-o\s+([a-zA-Z0-9_]+)(?:$|\b|\s).*')
    REGEX_IPTABLES_INPUT = re.compile(r'.*?(?:^|\b|\s)-A\s+INPUT(?:$|\b|\s).*')
    REGEX_IPTABLES_PROTO = r'.*?(?:^|\b|\s)-p\s+%s(?:$|\b|\s).*'
    REGEX_IPTABLES_PORT = r'.*?(?:^|\b|\s)--dport\s+%d(?:$|\b|\s).*'
    REGEX_IPTABLES_ACCEPT = re.compile(r'.*?(?:^|\b|\s)-j\s+ACCEPT(?:$|\b|\s).*')

    def __init__(self, print_output=False, audit=None, *args, **kwargs):
        self.print_output = print_output
        self.write_dots = False

        self.audit = audit
        if self.audit is None:
            self.audit = AuditManager(disabled=True)

        self.os = osutil.get_os()
        self.audit.audit_value(os=self.os.to_json())
        logger.debug('OS detection, name: %s, version: %s, version major: %s, like: %s, packager: %s, '
                     'start system: %s' % (self.os.name, self.os.version, self.os.version_major,
                                           self.os.like, self.os.packager, self.os.start_system))

        # Firewall name -> set enabled in the system.
        # Not to repeat the same enable action
        self.firewall_enabled = {}

    #
    # Execution
    #

    def exec_shell_open(self, cmd_exec, shell=True, stdin=None, stdout=None, stderr=None):
        """
        Simple execution wrapper with audit logging.
        :param cmd_exec:
        :param shell:
        :param stdin:
        :param stdout:
        :param stderr:
        :return: subprocess
        """
        self.audit.audit_exec(cmd_exec, stdin=stdin, stdout=stdout, stderr=stderr)

        logger.debug('Execute: %s' % cmd_exec)
        p = subprocess.Popen(cmd_exec, shell=shell, stdin=stdin, stdout=stdout, stderr=stderr)
        return p

    def exec_shell_subprocess(self, cmd_exec, shell=True, stdin_string=None):
        """
        Simple execution wrapper with audit logging, executes the command, returns return code.
        Uses subprocess.Popen()
        :param cmd_exec:
        :param shell:
        :param stdin_string: string to pass to the stdin
        :return: return code
        """
        stdin = None if stdin_string is None else subprocess.PIPE
        stdout = None if stdin_string is None else subprocess.PIPE
        stderr = None if stdin_string is None else subprocess.PIPE
        p = self.exec_shell_open(cmd_exec=cmd_exec, shell=shell, stdin=stdin, stdout=stdout, stderr=stderr)

        input = None if stdin_string is None else stdin_string
        sout, serr = p.communicate(input=input)

        self.audit.audit_exec(cmd_exec, retcode=p.returncode, stdout=sout, stderr=serr, stdin_string=stdin_string)
        return p.returncode

    def exec_shell(self, cmd_exec, shell=True, write_dots=None, sensitive=None):
        """
        Simple execution wrapper with audit logging, executes the command, returns return code
        :param cmd_exec:
        :param shell:
        :param write_dots:
        :param sensitive:
        :return: return code
        """
        ret = self.cli_cmd_sync(cmd_exec, shell=shell, write_dots=write_dots)
        return ret[0]

    def cli_cmd_sync(self, cmd, log_obj=None, write_dots=None, on_out=None, on_err=None, cwd=None, shell=True,
                     sensitive=None):
        """
        Runs command line task synchronously
        :return: ret_code, stdout, stderr
        """
        self.audit.audit_exec(cmd, cwd=cwd)
        logger.debug('Execute: %s' % cmd)

        if write_dots is None:
            write_dots = self.write_dots

        ret = None
        try:
            ret = util.cli_cmd_sync(cmd=cmd, log_obj=log_obj, write_dots=write_dots,
                                    on_out=on_out, on_err=on_err, cwd=cwd, shell=shell)

            ret_code, out_acc, err_acc = ret
            self.audit.audit_exec(cmd, cwd=cwd, retcode=ret_code, stdout=out_acc, stderr=err_acc)

        except Exception as e:
            self.audit.audit_exec(cmd, cwd=cwd, exception=e, exctrace=traceback.format_exc())
            raise
        return ret

    #
    # Memory
    #

    def get_virt_mem(self):
        return psutil.virtual_memory().total

    def get_swap_mem(self):
        return psutil.swap_memory().total

    def get_total_usable_mem(self):
        """
        Virtual Memory + Swap
        :return:
        """
        return self.get_virt_mem() + self.get_swap_mem()

    def is_enough_ram(self):
        """
        Return true if there is at least 2GB RAM available (RAM+SWAP)
        :return:
        """
        return self.get_total_usable_mem() >= 1024*1024*1024*1.9

    def get_swap_size_needed(self):
        """
        Returns number of bytes a swap file should have so we can finish the installation.
        Minimally we add 1GB of swap.
        :return:
        """
        base = int(1024*1024*1024*1.5)

        # If virt mem is < 1GB, add the difference
        virt_mem = self.get_virt_mem()
        if virt_mem < 1024*1024*1024*0.9:
            base += 1024*1024*1024 - virt_mem

        return base

    def create_swap(self, swap_file='/var/swap.bin', desired_size=None):
        """
        If size is none, optimal size is computed.

        dd if=/dev/zero of=/var/swap.1 bs=1M count=1024
        chmod 0600 /var/swap.1
        mkswap /var/swap.1
        swapon /var/swap.1
        echo '/var/swap.1 swap swap defaults 0 0' >> /etc/fstab
        :return:
        """
        if desired_size is None:
            desired_size = self.get_swap_size_needed()

        size_in_mb = int(math.ceil(desired_size/1024/1024))

        # Get unique swap file name
        fhnd, fname = util.unique_file(swap_file, mode=0o600)
        path, tail = os.path.split(fname)
        fhnd.close()

        # Check if there is enough free space + 128MB extra
        fs_stats = psutil.disk_usage(path)
        size_required = desired_size+1024*1024*128

        if fs_stats.free < size_required:
            sys.stderr.write('Not enough free space in %s required: %d, free: %s\n' % (path, size_required, fs_stats.free))
            return -1

        # Create swap file
        cmd = '/bin/rm "%s" && ' % fname
        cmd += ' dd if=/dev/zero of="%s" bs=1M count=%d >/dev/null && ' % (fname, size_in_mb)
        cmd += ' chmod 600 %s >/dev/null && ' % fname
        cmd += ' mkswap %s >/dev/null && ' % fname
        cmd += ' swapon %s >/dev/null && ' % fname
        cmd += ' echo "%s swap swap defaults 0 0" >> /etc/fstab ' % fname
        cmd_exec = 'sudo -E -H /bin/bash -c \'%s\'' % cmd

        # Swap create
        return_code = self.exec_shell(cmd_exec)
        return return_code, fname, desired_size

    def print_error(self, msg):
        if self.print_output:
            sys.stderr.write(msg)

    #
    # Wrapper scripts
    #
    def get_wrapper_script(self, install_type=None):
        """
        Returns a wrapper script full path for the given install type
        :param type:
        :return:
        """
        if install_type is None or install_type in ['pki', 'ejbca']:
            return '/usr/sbin/ebstall-pki'
        elif install_type in ['vpn', 'privspace']:
            return '/usr/sbin/ebstall-privspace'
        else:
            raise ValueError('Unknown installation type: %s' % install_type)

    #
    # Cron
    #

    def get_cron_file(self, file_name):
        """
        Returns cron file path
        :param file_name:
        :return:
        """
        return os.path.join('/etc/cron.d', os.path.basename(file_name))

    def delete_cron_file(self, cron_path):
        """
        Deletes cron file
        :param cron_path:
        :return:
        """
        if os.path.exists(cron_path):
            os.remove(cron_path)
            self.audit.audit_delete(cron_path)

    def install_crond_file(self, file_name, file_contents):
        """
        Installs a new cron.d file name.
        Overwrites existing.
        :param file_name:
        :param file_contents:
        :return:
        """
        cron_path = self.get_cron_file(file_name)
        self.delete_cron_file(cron_path)

        with util.safe_open(cron_path, mode='w', chmod=0o644) as handle:
            handle.write(file_contents)
        self.audit.audit_file_write(cron_path)
        return 0

    def remove_cron_renew(self):
        """
        Removes previous cron file
        :return:
        """
        cron_path = self.get_cron_file('ebstall-renew')
        self.delete_cron_file(cron_path)

    def install_cron_renew(self, install_type=None):
        """
        Installs cronjob for certificate renewal
        :return:
        """
        wrapper_path = self.get_wrapper_script(install_type=install_type)
        data = '# Daily certificate renewal for the PKI key management system (EJBCA LetsEncrypt)\n'
        data += '*/5 * * * * root %s --no-self-upgrade -n --pid-lock 3 renew >/dev/null 2>/dev/null \n' % wrapper_path

        return self.install_crond_file('ebstall-renew', data)

    #
    # OR detection / specific settings
    #
    def get_os(self):
        """
        Returns the OS detection result
        :return:
        """
        return self.os

    def get_packager(self):
        """
        Returns package manager for the current OS
        :return:
        """
        return self.os.packager

    def get_start_system(self):
        """
        Returns start system (init.d/systemd) for the current OS
        :return:
        """
        return self.os.start_system

    def _get_svc_desc(self, svcmap, start_system):
        """
        Gets service identifier from the argument.
        May be a simple value or a dictionary[start-system].
        The service name can also differ among OSes, but this is not addressed for now.

        :param svcmap:
        :param start_system:
        :return:
        """
        if isinstance(svcmap, types.DictionaryType):
            try:
                return svcmap[start_system]
            except (KeyError, TypeError):
                pass

        if not isinstance(svcmap, basestring):
            raise ValueError('Incorrect service specification')

        if start_system == osutil.START_SYSTEMD \
                and not svcmap.endswith('.service') \
                and not svcmap.endswith('.daemon'):
            svcmap += '.service'
        return svcmap

    #
    # System changes / services
    #

    def _get_systemd_svc_state(self, svc):
        """
        Runs systemctl and obtains service state
        :param svc:
        :return: (loadState, activeState)
        """
        cmd = 'sudo systemctl show ' + svc
        ret, stdout, stderr = self.cli_cmd_sync(cmd, shell=True)

        if ret != 0:
            logger.debug('Error executing systemctl show command, code: %d' % ret)
            return None, None

        load_state = None
        active_state = None

        lines = [x.strip() for x in stdout.split('\n')]
        for line in lines:
            parts = line.split('=', 2)
            if len(parts) < 2:
                continue

            cmd, val = [x.strip().lower() for x in parts]
            if cmd == 'loadstate':
                load_state = val
            if cmd == 'activestate':
                active_state = val
        return load_state, active_state

    def enable_svc(self, svcmap, enable=True):
        """
        Enables given service after OS start
        :param svcmap:
        :return:
        """
        start_system = self.get_start_system()
        svc = self._get_svc_desc(svcmap, start_system)
        cmd_exec = None

        if start_system == osutil.START_INITD:
            enable_cmd = 'on' if enable else 'off'
            cmd_exec = 'sudo chkconfig --level=345 \'%s\' %s' % (svc, enable_cmd)
        elif start_system == osutil.START_SYSTEMD:
            enable_cmd = 'enable' if enable else 'disable'
            cmd_exec = 'sudo systemctl %s \'%s\'' % (enable_cmd, svc)
        else:
            raise OSError('Cannot enable service in this OS')

        return self.exec_shell(cmd_exec)

    def switch_svc(self, svcmap, start=None, stop=None, restart=None):
        """
        Changes service state - starts, stops or restarts the service
        :param svcmap: service name definition. string or service map init system -> service name.
        :param start:
        :param stop:
        :param restart:
        :return:
        """
        check = 0
        check += 1 if start is not None else 0
        check += 1 if stop is not None else 0
        check += 1 if restart is not None else 0
        if check != 1:
            raise ValueError('Exactly one of start, stop, restart has to be set to True')

        start_system = self.get_start_system()
        svc = self._get_svc_desc(svcmap, start_system)
        cmd_exec = None

        change_state = 'start'
        if stop:
            change_state = 'stop'
        elif restart:
            change_state = 'restart'

        if start_system == osutil.START_INITD:
            cmd_exec = 'sudo /etc/init.d/%s %s' % (svc, change_state)
        elif start_system == osutil.START_SYSTEMD:
            cmd_exec = 'sudo systemctl %s \'%s\'' % (change_state, svc)
        else:
            raise OSError('Cannot enable service in this OS')

        return self.exec_shell(cmd_exec)

    def svc_status(self, svcmap):
        """
        Returns True if the service is running.
        Using init.d or systemctl status
        :param svcmap: service name definition. string or service map init system -> service name.
        :return: (found, running)
        """
        start_system = self.get_start_system()
        svc = self._get_svc_desc(svcmap, start_system)

        if start_system == osutil.START_INITD:
            initd_path = os.path.join('/etc/init.d/', svc)
            if not os.path.exists(initd_path):
                return False, False

            cmd_exec = 'sudo %s status' % initd_path
            ret = self.exec_shell(cmd_exec, shell=True)
            return True, ret == 0

        elif start_system == osutil.START_SYSTEMD:
            load_state, active_state = self._get_systemd_svc_state(svc)
            loaded = load_state == 'loaded'
            if not loaded:
                return False, False

            active = active_state == 'active'
            return True, active

        else:
            raise OSError('Cannot enable service in this OS')

    def svc_is_installed(self, svcmap):
        """
        Returns true if the service is installed in the start system
        :param svcmap:
        :return:
        """
        loaded, active = self.svc_status(svcmap=svcmap)
        return loaded == True

    def svc_is_running(self, svcmap):
        """
        Returns true if the service is running, false otherwise
        :param svcmap:
        :return:
        """
        loaded, active = self.svc_status(svcmap=svcmap)
        return (loaded and active) == True

    def install_onboot_check(self, install_type=None):
        """
        Installs a service invocation after boot to reclaim domain again
        :return:
        """
        if self.os.start_system == osutil.START_SYSTEMD:
            return self.install_onboot_check_systemd(install_type=install_type)

        # Fallback to default initd start system
        return self.install_onboot_check_initd(install_type=install_type)

    def install_onboot_check_systemd(self, install_type=None):
        """
        Installs onboot check in systemd (centos/rhell 7+)
        :return:
        """
        # Write simple init script
        wrapper_path = self.get_wrapper_script(install_type=install_type)
        initd_path = '/etc/systemd/system/enigmabridge-onboot.service'
        if os.path.exists(initd_path):
            os.remove(initd_path)
            self.audit.audit_delete(initd_path)

        with util.safe_open(initd_path, mode='w', chmod=0o664) as handle:
            data = self.get_onboot_init_systemd_script()
            data = data.replace('{{ wrapper_path }}', wrapper_path)
            handle.write(data)
            handle.write('\n')
        self.audit.audit_file_write(initd_path)

        # Set service to start after boot
        ret = self.exec_shell('sudo systemctl daemon-reload')
        if ret != 0:
            self.print_error('Error: Could not reload systemctl, code: %s\n' % ret)
            return 2

        ret = self.exec_shell('sudo systemctl enable enigmabridge-onboot', shell=True)
        if ret != 0:
            self.print_error('Error: Could not install on boot system service, code: %s\n' % ret)
            return 2

        return 0

    def install_onboot_check_initd(self, install_type=None):
        """
        Installs onboot check in initd system
        :return:
        """
        # Write simple init script
        wrapper_path = self.get_wrapper_script(install_type=install_type)
        initd_path = '/etc/init.d/enigmabridge-onboot'
        if os.path.exists(initd_path):
            os.remove(initd_path)
            self.audit.audit_delete(initd_path)

        with util.safe_open(initd_path, mode='w', chmod=0o755) as handle:
            data = self.get_onboot_init_script()
            data = data.replace('{{ wrapper_path }}', wrapper_path)
            handle.write(data)
            handle.write('\n')
        self.audit.audit_file_write(initd_path)

        # Set service to start after boot
        ret = self.exec_shell('sudo chkconfig --level=345 enigmabridge-onboot on', shell=True)
        if ret != 0:
            self.print_error('Error: Could not install on boot system service, code: %s\n' % ret)
            return 2

        return 0

    def get_onboot_init_script(self):
        """
        Returns a static asset - init script
        Contains template variable {{ wrapper_path }}
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('consts', 'eb-init.sh'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def get_onboot_init_systemd_script(self):
        """
        Returns a static asset - systemd start script
        Contains template variable {{ wrapper_path }}
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('consts', 'eb-systemd.sh'))
        return pkg_resources.resource_string(resource_package, resource_path)

    #
    # Networking / Firewall
    #

    def is_port_listening(self, port, tcp=True):
        """
        Returns a connection if the given port is listening locally, None otherwise
        :param port:
        :param tcp:
        :return:
        """
        is_listening = util.is_port_listening(port=port, tcp=tcp)
        self.audit.audit_evt('port-listening', port=port, tcp=True, is_listening=is_listening)
        return is_listening

    def packet_forwarding(self, enable=True):
        """
        Enable packet forwarding
        net.ipv4.ip_forward = 1

        :param enable:
        :return: 0 on success, otherwise error. Exception may happen.
        """
        sysctl = '/etc/sysctl.conf'
        new_data = []

        with open(sysctl, 'r') as fh:
            data = fh.readlines()
            self.audit.audit_file_read(sysctl, data=data)

            was_fixed = False
            for line in data:
                if len(line.strip()) == 0:
                    new_data.append(line)
                    continue
                if re.match(r'^\s*#.*$', line):
                    new_data.append(line)
                    continue
                if re.match(r'^net\.ipv4\.ip_forward', line):
                    new_data.append('net.ipv4.ip_forward = %d\n' % (1 if enable else 0))
                    was_fixed = True
                else:
                    new_data.append(line)

            if not was_fixed:
                new_data.append('net.ipv4.ip_forward = %d\n' % (1 if enable else 0))

        with open(sysctl, 'w') as fh:
            fh.write(''.join(new_data))
            self.audit.audit_file_write(sysctl, data=new_data)

        ret = self.exec_shell('sudo sysctl -p', shell=True)
        return ret

    def get_firewall(self):
        """
        Gets the installed firewall info.

        :return: [(firewall-type, running)]
        """
        # TODO: allow override via cmdline / configuration

        results = []
        firewalls = []
        start_system = self.get_start_system()
        if start_system == osutil.START_SYSTEMD:
            firewalls = [FIREWALL_FIREWALLD, FIREWALL_UFW, FIREWALL_IPTABLES]
        else:
            firewalls = [FIREWALL_FIREWALLD, FIREWALL_UFW, FIREWALL_IPTABLES]

        for fw in firewalls:
            loaded, active = self.svc_status(fw)
            if not loaded:
                continue
            results.append((fw, active))

        # Sort by running
        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _get_default_firewall(self):
        """
        Returns default firewall for the current OS
        :return:
        """
        if self.os.family == osutil.FAMILY_DEBIAN:
            if self.get_start_system() == osutil.START_SYSTEMD:
                return FIREWALL_UFW
            else:
                return FIREWALL_IPTABLES

        elif self.os.family == osutil.FAMILY_REDHAT:
            if self.get_start_system() == osutil.START_SYSTEMD:
                return FIREWALL_FIREWALLD
            else:
                return FIREWALL_IPTABLES

        else:
            self.audit.audit_evt('unknown-family', family=self.os.family, context='Default firewall detection')
            logger.debug('Unknown family for firewall detection: %s' % self.os.family)

            return FIREWALL_IPTABLES

    def _install_firewall(self, preference=None, enable=True, start=True):
        """
        Installs missing firewall.
        Should be run only if the firewall is not already installed
        :return:
        """
        pkg = self.get_packager()

        firewall_to_install = util.strip(preference)
        if firewall_to_install is None:
            firewall_to_install = self._get_default_firewall()
        if firewall_to_install not in FIREWALLS:
            raise ValueError('Unknown firewall to install: %s' % firewall_to_install)

        ret = None
        if pkg == osutil.PKG_YUM:
            ret = self.exec_shell('sudo yum install -y %s' % firewall_to_install)
        elif pkg == osutil.PKG_APT:
            ret = self.exec_shell('sudo apt-get install -y %s' % firewall_to_install)
        else:
            raise OSError('Unknown package manager, cannot install firewall %s' % firewall_to_install)

        if ret != 0:
            raise OSError('Could not install firewall %s' % firewall_to_install)

        # Enable
        if enable:
            ret = self.enable_svc(firewall_to_install, True)
            if ret != 0:
                raise OSError('Could not enable firewall %s' % firewall_to_install)

        # Start
        if start:
            ret = self.switch_svc(firewall_to_install, restart=True)
            if ret != 0:
                raise OSError('Could not start firewall %s' % firewall_to_install)

        return 0

    def _get_routes(self):
        """
        ip route
        :return:
        """
        ret, stdout, stderr = self.cli_cmd_sync('sudo ip route')
        if ret != 0:
            raise OSError('Could not get routes')

        return [x.strip() for x in stdout]

    def _get_default_dev(self):
        """
        Default device - e.g., eth0
        :return:
        """
        routes = self._get_routes()
        for route in routes:
            if not route.startswith('default'):
                continue

            m = re.match(r'.+?\bdev\s+([^\s]+?)\b', route)
            if m is not None:
                return m.group(1)

    def _try_get_default_dev(self):
        """
        Tries to obtain default gateway device, returns None if cannot detect.
        :return:
        """
        try:
            return self._get_default_dev()
        except Exception as e:
            self.audit.audit_exception()
            logger.debug('Cannot obtain default device %s' % e)
        return None

    def _resolve_firewalls(self, enable=True, start=True):
        """
        Tries to get the firewall used on the system, install one if there is none.
        Enables firewall after the OS start, restarts the firewall if it is not running.
        :param: enable if true the firewall is enabled to start after boot
        :param: start if true the firewall is restarted if not running
        :return: firewall name
        """
        firewalls = self.get_firewall()

        if len(firewalls) == 0:
            logger.debug('No firewall / iptables detected. ')
            self.audit.audit_evt('no-firewalls')

            self._install_firewall()
            firewalls = self.get_firewall()

        if len(firewalls) == 0:
            logger.debug('Firewall installation failed')
            self.audit.audit_evt('no-firewalls-end')
            raise OSError('Could not get firewall running')

        if len(firewalls) > 1:
            logger.debug('Multiple firewalls detected: %s' % firewalls)
            self.audit.audit_evt('multiple-firewalls', firewalls=firewalls)

        fw_name, fw_running = firewalls[0]
        self.audit.audit_evt('firewall', firewall=fw_name, running=fw_running)

        if enable and fw_name not in self.firewall_enabled or not self.firewall_enabled[fw_name]:
            ret = self.enable_svc(fw_name, True)
            if ret != 0:
                raise OSError('Could not enable firewall %s' % fw_name)
            self.firewall_enabled[fw_name] = True

        if start and not fw_running:
            ret = self.switch_svc(fw_name, restart=True)
            if ret != 0:
                raise OSError('Could not start firewall %s' % fw_name)

        return fw_name

    def masquerade(self, net, net_size):
        """
        Add firewall masquerade rule - NATing
        :param net:
        :param net_size:
        :return:
        """
        fw_name = self._resolve_firewalls()

        if fw_name == FIREWALL_UFW:
            return self._masquerade_ufw(net=net, net_size=net_size)
        elif fw_name == FIREWALL_FIREWALLD:
            return self._masquerade_firewalld(net=net, net_size=net_size)
        elif fw_name == FIREWALL_IPTABLES:
            return self._masquerade_iptables(net=net, net_size=net_size)
        else:
            raise EnvironmentError('Unknown firewall %s' % fw_name)

    def _ufw_accept_forward(self):
        """
        Changes UFW configuration so it accepts forwarding
        DEFAULT_FORWARD_POLICY="ACCEPT"
        :return:
        """
        default_ufw = '/etc/default/ufw'
        new_data = []

        with open(default_ufw, 'r') as fh:
            data = fh.readlines()
            self.audit.audit_file_read(default_ufw, data=data)

            was_changed = False
            for line in data:
                match = re.match(r'^DEFAULT_FORWARD_POLICY\s*=(.+?)\s*$', line)
                if match:
                    cur = match.group(1).strip().lower()
                    if cur in ['accept', '"accept"', "'accept'"]:
                        logger.debug('UFW already set to forward')
                        return 0

                    else:
                        new_data.append('DEFAULT_FORWARD_POLICY="ACCEPT"\n')
                        was_changed = True
                else:
                    new_data.append(line)

            if not was_changed:
                new_data.append('DEFAULT_FORWARD_POLICY="ACCEPT"\n')

        with open(default_ufw, 'w') as fh:
            fh.write(''.join(new_data))
            self.audit.audit_file_write(default_ufw, data=new_data)

    def _ufw_get_before_rules(self):
        """
        Loads /etc/ufw/before.rules
        :return:
        """
        # Analyze if not present already
        ret, stdout, stderr = self.cli_cmd_sync('sudo cat /etc/ufw/before.rules')
        if ret != 0:
            raise OSError('Cannot load /etc/ufw/before.rules')
        return [x.strip() for x in stdout]

    def _ufw_save_before_rules(self, new_lines):
        """
        Updates /etc/ufw/before.rules
        :param new_lines:
        :return:
        """
        util.make_or_verify_dir(self.SYSCONFIG_BACKUP, mode=0o750)
        fh, backup = util.safe_create_with_backup('/etc/ufw/before.rules', mode='w', chmod=0o640,
                                                  backup_dir=self.SYSCONFIG_BACKUP)
        with fh:
            pass

        new_content = '\n'.join(x.strip() for x in new_lines)
        ret = self.exec_shell_subprocess(cmd_exec='sudo tee /etc/ufw/before.rules > /dev/null', shell=True,
                                         stdin_string=new_content)
        if ret != 0:
            raise OSError('Cannot save new /etc/ufw/before.rules')
        return 0

    def _ufw_masquerade_before_rules(self, net, net_size, default_dev):
        """
        Adds masquerade to the before rules
        :return:
        """
        before_rules = self._ufw_get_before_rules()
        net_desc = '%s/%d' % (net, net_size)

        is_there = None
        nat_idx_start = None
        nat_commit_idx = None
        nat_postrouting_accept = None
        first_non_comment = None

        is_nat = False
        for idx, rule in enumerate(before_rules):
            if re.match(r'^\s*#.*', rule):
                continue

            if first_non_comment is None:
                first_non_comment = idx

            if len(rule) == 0:
                continue

            # Table name
            m_sec = re.match(r'^\*(.+?)$', rule)
            if m_sec is not None:
                is_nat = util.strip(m_sec.group(1)) == 'nat'

            # Interested only in NAT table
            if not is_nat:
                continue

            if nat_idx_start is None:
                nat_idx_start = idx

            rlow = rule.lower()
            if rlow == 'commit':
                if nat_commit_idx is None:
                    nat_commit_idx = idx
                continue

            if re.match(r'\s*:\s*POSTROUTING ACCEPT \[0:0\]\s*', re.IGNORECASE):
                nat_postrouting_accept = idx
                continue

            # Particular rule
            m_routing = re.match(self.REGEX_IPTABLES_POSTROUTING, rule)
            m_mask = re.match(self.REGEX_IPTABLES_MASQUERADE, rule)
            m_src = re.match(self.REGEX_IPTABLES_SRC % re.escape(net_desc), rule)
            m_out = re.match(self.REGEX_IPTABLES_OUTPUT_DEV, rule)

            if m_routing is None or m_mask is None or m_src is None:
                continue

            if m_out is None or m_out.group(1) == default_dev:
                is_there = rule

        # Adding a new rule to the file
        idx_offset = 0
        if is_there:
            logger.debug('Masquerade rule is already added')
            return 0

        if nat_idx_start is not None and nat_commit_idx is None:
            logger.debug('NAT table exists, but without commit')
            raise EnvironmentError('Cannto modify UFW before rules to add masquerade rules')

        if nat_idx_start is not None and nat_commit_idx is not None and nat_postrouting_accept is None:
            before_rules.insert(nat_idx_start + 1, ':POSTROUTING ACCEPT [0:0]')
            idx_offset += 1

        dev_part = '' if default_dev is None else ' -o %s' % default_dev
        new_rule = '-A POSTROUTING -s %s%s -j MASQUERADE' % (net_desc, dev_part)

        if nat_commit_idx is not None:
            before_rules.insert(nat_commit_idx + idx_offset, new_rule)

        else:
            new_lines = ['# START OPENVPN RULES',
                         '# NAT table rules',
                         '*nat',
                         ':POSTROUTING ACCEPT [0:0] ',
                         '# Allow traffic from OpenVPN client',
                         new_rule,
                         'COMMIT',
                         '# END OPENVPN RULES']

            before_rules = before_rules[:first_non_comment] + new_lines + before_rules[first_non_comment:]

        # Flush before-rules to the config file.
        return self._ufw_save_before_rules(before_rules)

    def _ufw_reload(self):
        """
        Reloads UFW firewall rules
        :return:
        """
        ret = self.exec_shell('sudo ufw disable', shell=True)
        if ret != 0:
            raise OSError('Cannot reload ufw (disable step)')

        ret = self.exec_shell('sudo ufw enable', shell=True)
        if ret != 0:
            raise OSError('Cannot reload ufw (enable step)')

    def _iptables_get_rules(self, flush=False):
        """
        Gets current iptables rules as lines.
        Throws an exception if dump cannot be done.
        :param flush: if true iptables rules are flushed (removed)
        :return:
        """
        if flush:
            cmd = 'sudo iptables --flush'
            ret = self.exec_shell(cmd, shell=True)
            if ret != 0:
                raise OSError('Cannot flush iptables')

        # Analyze if not present already
        ret, stdout, stderr = self.cli_cmd_sync('sudo iptables-save')
        if ret != 0:
            raise OSError('Cannot get current iptables state')
        return [x.strip() for x in stdout]

    def _iptables_save(self):
        """
        Saves in-memory iptables rules to the file
        :return:
        """
        ret = self.exec_shell('sudo iptables-save | sudo tee /etc/sysconfig/iptables >/dev/null', shell=True)
        if ret != 0:
            raise OSError('Cannot save new iptables rules')
        return 0

    def _masquerade_ufw(self, net, net_size):
        """
        Adds masquerade rules to the UFW (Universal firewall)
        :param net:
        :param net_size:
        :return:
        """
        default_dev = self._try_get_default_dev()

        # Set policy to accept forwarding
        self._ufw_accept_forward()

        # Update before rules - add a masquerade rule to the table
        self._ufw_masquerade_before_rules(net, net_size, default_dev)

        # Reload rules
        self._ufw_reload()
        self.audit.audit_evt('firewall-modified', rule='add-masquerade', firewall=FIREWALL_UFW)
        return 0

    def _masquerade_iptables(self, net, net_size):
        """
        Adds masquerade rules to the iptables - permanent.
        :param net:
        :param net_size:
        :return:
        """

        default_dev = self._try_get_default_dev()
        iptables_rules = self._iptables_get_rules()

        is_there = None
        net_desc = '%s/%d' % (net, net_size)
        is_nat = False
        for rule in iptables_rules:
            if len(rule) == 0:
                continue
            if re.match(r'^\s*#.*', rule):
                continue
            if rule.startswith(':'):
                continue

            rlow = rule.lower()
            if rlow == 'commit':
                continue

            m_sec = re.match(r'^\*(.+?)$', rule)
            if m_sec is not None:
                is_nat = util.strip(m_sec.group(1)) == 'nat'

            if not is_nat:
                continue

            m_routing = re.match(self.REGEX_IPTABLES_POSTROUTING, rule)
            m_mask = re.match(self.REGEX_IPTABLES_MASQUERADE, rule)
            m_src = re.match(self.REGEX_IPTABLES_SRC % re.escape(net_desc), rule)
            m_out = re.match(self.REGEX_IPTABLES_OUTPUT_DEV, rule)

            if m_routing is None or m_mask is None or m_src is None:
                continue

            if m_out is None or m_out.group(1) == default_dev:
                is_there = rule

        if is_there is None:
            dev_part = '' if default_dev is None else ' -o %s' % default_dev
            new_rule = '-A POSTROUTING -s %s%s -j MASQUERADE' % (net_desc, dev_part)

            ret = self.exec_shell('sudo iptables -t nat %s' % new_rule, shell=True)
            if ret != 0:
                raise OSError('Cannot add a new rule to iptables: %s' % new_rule)

            self._iptables_save()
            self.audit.audit_evt('firewall-modified', rule=new_rule, firewall=FIREWALL_IPTABLES)
            logger.debug('Rule added to iptables %s' % new_rule)

        else:
            logger.debug('Rule already there: %s' % is_there)

        return 0

    def _masquerade_firewalld(self, net, net_size):
        """
        Adds masquerade rules to the firewalld
        :param net:
        :param net_size:
        :return:
        """
        cmd = 'sudo firewall-cmd --permanent --zone=external --add-masquerade'
        ret = self.exec_shell(cmd, shell=True)
        if ret == 0:
            self.audit.audit_evt('firewall-modified', rule='--add-masquerade', firewall=FIREWALL_FIREWALLD)

        self.audit.audit_evt('firewall-modified', rule='add-masquerade', firewall=FIREWALL_FIREWALLD)
        return ret

    def allow_port(self, port, tcp=True, reload=True):
        """
        Allows given port to the public
        :param port:
        :param tcp:
        :return:
        """
        fw_name = self._resolve_firewalls()

        if fw_name == FIREWALL_UFW:
            return self._allow_ufw(port=port, tcp=tcp, reload=reload)
        elif fw_name == FIREWALL_FIREWALLD:
            return self._allow_firewalld(port=port, tcp=tcp, reload=reload)
        elif fw_name == FIREWALL_IPTABLES:
            return self._allow_iptables(port=port, tcp=tcp, reload=reload)
        else:
            raise EnvironmentError('Unknown firewall %s' % fw_name)

    def _allow_ufw(self, port, tcp=True, reload=True):
        """
        Adds port allow rule to the UFW
        :param port:
        :param tcp:
        :param reload:
        :return:
        """
        port_desc = '%d/%s' % (port, 'tcp' if tcp else 'udp')

        ret = self.exec_shell('sudo ufw allow %s' % port_desc, shell=True)
        if ret != 0:
            raise OSError('Cannot add ufw allow rule')

        self.audit.audit_evt('firewall-modified', rule='allow-port', port=port, tcp=tcp, firewall=FIREWALL_UFW)
        return 0

    def _allow_firewalld(self, port, tcp=True, reload=True):
        """
        Adds port allow rule to the firewalld
        :param port:
        :param tcp:
        :param reload:
        :return:
        """
        port_desc = '%d/%s' % (port, 'tcp' if tcp else 'udp')
        ret = self.exec_shell('sudo firewall-cmd --permanent --zone=public --add-port=%s' % port_desc, shell=True)
        if ret != 0:
            raise OSError('Cannot add ufw allow rule')

        self.audit.audit_evt('firewall-modified', rule='allow-port', port=port, tcp=tcp, firewall=FIREWALL_FIREWALLD)
        return 0

    def _allow_iptables(self, port, tcp=True, reload=True):
        """
        Adds port allow rule to the iptables
        :param port:
        :param tcp:
        :param reload:
        :return:
        """
        rules = self._iptables_get_rules()
        proto = 'tcp' if tcp else 'udp'
        ' -A INPUT -m state --state NEW -m tcp -p tcp --dport 25 -j ACCEPT'

        is_there = None
        is_filter = False
        for rule in rules:
            if len(rule) == 0:
                continue
            if re.match(r'^\s*#.*', rule):
                continue
            if rule.startswith(':'):
                continue
            if rule.lower() == 'commit':
                continue

            m_sec = re.match(r'^\*(.+?)$', rule)
            if m_sec is not None:
                is_filter = util.strip(m_sec.group(1)) == 'filter'
            if not is_filter:
                continue

            m_input = re.match(self.REGEX_IPTABLES_INPUT, rule)
            m_proto = re.match(self.REGEX_IPTABLES_PROTO % proto, rule, re.IGNORECASE)
            m_port = re.match(self.REGEX_IPTABLES_PORT % port, rule)
            m_accept = re.match(self.REGEX_IPTABLES_ACCEPT, rule)

            if m_input is None or m_proto is None or m_port is None or m_accept is None:
                continue
            is_there = True
            break

        if is_there is None:
            new_rule = '-A INPUT -m state --state NEW -m tcp -p tcp --dport %s -j ACCEPT' % port
            if not tcp:
                new_rule = '-A INPUT -m udp -p udp --dport %s -j ACCEPT' % port

            ret = self.exec_shell('sudo iptables %s' % new_rule, shell=True)
            if ret != 0:
                raise OSError('Cannot add a new rule to iptables: %s' % new_rule)

            self._iptables_save()
            self.audit.audit_evt('firewall-modified', rule=new_rule, firewall=FIREWALL_IPTABLES)
            self.audit.audit_evt('firewall-modified', rule='allow-port', port=port, tcp=tcp, firewall=FIREWALL_IPTABLES)
            logger.debug('Rule added to iptables %s' % new_rule)

        else:
            logger.debug('Rule already there: %s' % is_there)

        return 0





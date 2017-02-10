#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

import ebaws.osutil
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

    #
    # Execution
    #

    def exec_shell_open(self, cmd_exec, shell=True):
        """
        Simple execution wrapper with audit logging.
        :param cmd_exec:
        :param shell:
        :return: subprocess
        """
        self.audit.audit_exec(cmd_exec)

        logger.debug('Execute: %s' % cmd_exec)
        p = subprocess.Popen(cmd_exec, shell=shell)
        return p

    def exec_shell_subprocess(self, cmd_exec, shell=True):
        """
        Simple execution wrapper with audit logging, executes the command, returns return code.
        Uses subprocess.Popen()
        :param cmd_exec:
        :param shell:
        :return: return code
        """
        p = self.exec_shell_open(cmd_exec=cmd_exec, shell=shell)
        p.communicate()

        self.audit.audit_exec(cmd_exec, retcode=p.returncode)
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
        return self.get_total_usable_mem() >= 1024*1024*1024*1.6

    def get_swap_size_needed(self):
        """
        Returns number of bytes a swap file should have so we can finish the installation.
        Minimally we add 1GB of swap.
        :return:
        """
        base = 1024*1024*1024

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
    # Cron
    #

    def install_crond_file(self, file_name, file_contents):
        """
        Installs a new cron.d file name.
        Overwrites existing.
        :param file_name:
        :param file_contents:
        :return:
        """
        cron_path = os.path.join('/etc/cron.d', os.path.basename(file_name))
        if os.path.exists(cron_path):
            os.remove(cron_path)
            self.audit.audit_delete(cron_path)

        with util.safe_open(cron_path, mode='w', chmod=0o644) as handle:
            handle.write(file_contents)
        self.audit.audit_file_write(cron_path)
        return 0

    def install_cron_renew(self):
        """
        Installs cronjob for certificate renewal
        :return:
        """
        data = '# Daily certificate renewal for the PKI key management system (EJBCA LetsEncrypt)\n'
        data += '*/5 * * * * root /usr/local/bin/ebstall-cli -n --pid-lock 3 renew >/dev/null 2>/dev/null \n'

        return self.install_crond_file('ebaws-renew', data)

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
        try:
            return svcmap[start_system]
        except:
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

    def install_onboot_check(self):
        """
        Installs a service invocation after boot to reclaim domain again
        :return:
        """
        if self.os.start_system == osutil.START_SYSTEMD:
            return self.install_onboot_check_systemd()

        # Fallback to default initd start system
        return self.install_onboot_check_initd()

    def install_onboot_check_systemd(self):
        """
        Installs onboot check in systemd (centos/rhell 7+)
        :return:
        """
        # Write simple init script
        initd_path = '/etc/systemd/system/enigmabridge-onboot.service'
        if os.path.exists(initd_path):
            os.remove(initd_path)
            self.audit.audit_delete(initd_path)

        with util.safe_open(initd_path, mode='w', chmod=0o664) as handle:
            handle.write(self.get_onboot_init_script())
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

    def install_onboot_check_initd(self):
        """
        Installs onboot check in initd system
        :return:
        """
        # Write simple init script
        initd_path = '/etc/init.d/enigmabridge-onboot'
        if os.path.exists(initd_path):
            os.remove(initd_path)
            self.audit.audit_delete(initd_path)

        with util.safe_open(initd_path, mode='w', chmod=0o755) as handle:
            handle.write(self.get_onboot_init_script())
            handle.write('\n')
        self.audit.audit_file_write(initd_path)

        # Set service to start after boot
        ret = self.exec_shell('sudo chkconfig --level=345 enigmabridge-onboot on', shell=True)
        if ret != 0:
            self.print_error('Error: Could not install on boot system service, code: %s\n' % ret)
            return 2

        return 0

    def get_onboot_init_script(self):
        resource_package = __name__
        resource_path = '/'.join(('consts', 'eb-init.sh'))
        return pkg_resources.resource_string(resource_package, resource_path)

    def get_onboot_init_systemd_script(self):
        resource_package = __name__
        resource_path = '/'.join(('consts', 'eb-systemd.sh'))
        return pkg_resources.resource_string(resource_package, resource_path)

    #
    # Networking / Firewall
    #

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

        start_system = self.get_start_system()
        if start_system == osutil.START_SYSTEMD:

            firewalls = [FIREWALL_FIREWALLD, FIREWALL_UFW, FIREWALL_IPTABLES]
            for fw in firewalls:
                load_state, active_state = self._get_systemd_svc_state(fw)
                loaded = load_state == 'loaded'
                if not loaded:
                    continue

                active = active_state == 'active'
                results.append((fw, active))

        else:  # initd autodetect
            path_base = '/etc/init.d/'
            firewalls = [FIREWALL_FIREWALLD, FIREWALL_UFW, FIREWALL_IPTABLES]
            for fw in firewalls:
                init_file = os.path.join(path_base, fw)
                if not os.path.exists(init_file):
                    continue

                ret = self.exec_shell('sudo %s status' % init_file, shell=True)
                results.append((fw, ret == 0))

        # Sort by running
        results.sort(key=lambda x: x[1])
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
        start_system = self.get_start_system()

        firewall_to_install = util.strip(preference)
        if firewall_to_install is None:
            firewall_to_install = self._get_default_firewall()
        if firewall_to_install not in FIREWALLS:
            raise ValueError('Unknown firewall to install: %s' % firewall_to_install)

        ret = None
        if pkg == osutil.PKG_YUM:
            ret = self.exec_shell('sudo yum install -y %s' % firewall_to_install)
        elif pkg == osutil.PKG_APT:
            ret = self.exec_shell('sudo yum install -y %s' % firewall_to_install)
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

    def masquerade(self, net, net_size):
        """
        Add firewall masquerade rule
        :param net:
        :param net_size:
        :return:
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

        ret = self.enable_svc(fw_name, True)
        if ret != 0:
            raise OSError('Could not enable firewall %s' % fw_name)

        if not fw_running:
            ret = self.switch_svc(fw_name, restart=True)
            if ret != 0:
                raise OSError('Could not start firewall %s' % fw_name)

        if fw_name == FIREWALL_UFW:
            return self._masquerade_ufw(net=net, net_size=net_size)
        elif fw_name == FIREWALL_FIREWALLD:
            return self._masquerade_firewalld(net=net, net_size=net_size)
        elif fw_name == FIREWALL_IPTABLES:
            return self._masquerade_iptables(net=net, net_size=net_size)
        else:
            raise EnvironmentError('Unknown firewall %s' % fw_name)

    def _masquerade_ufw(self, net, net_size):
        """
        Adds masquerade rules to the UFW (Universal firewall)
        :param net:
        :param net_size:
        :return:
        """
        # TODO: implement

    def _masquerade_iptables(self, net, net_size):
        """
        Adds masquerade rules to the iptables
        :param net:
        :param net_size:
        :return:
        """
        # TODO: implement

    def _masquerade_firewalld(self, net, net_size):
        """
        Adds masquerade rules to the firewalld
        :param net:
        :param net_size:
        :return:
        """
        cmd = 'sudo firewall-cmd --permanent --zone=external --add-masquerade'
        ret = self.exec_shell(cmd, shell=True)
        return ret




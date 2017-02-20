#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import collections
import logging
import os
import platform
import re
import six
import stat
import subprocess
import sys
import errors
import shutil
import random
import string
from datetime import datetime
import time
import types
import util
from ebstall.util import normalize_string

logger = logging.getLogger(__name__)


CLI_DEFAULTS_DEFAULT = dict(
    packager='source'
)
CLI_DEFAULTS_DEBIAN = dict(
    packager='apt-get'
)
CLI_DEFAULTS_CENTOS = dict(
    packager='yum'
)
CLI_DEFAULTS_DARWIN = dict(
    packager='source'
)


FLAVORS = {
    'debian': 'debian',
    'ubuntu': 'debian',
    'kubuntu': 'debian',
    'kali': 'debian',

    'centos': 'redhat',
    'centos linux': 'redhat',
    'fedora': 'redhat',
    'red hat enterprise linux server': 'redhat',
    'rhel': 'redhat',
    'amazon': 'redhat',
    'amzn': 'redhat',

    'gentoo': 'gentoo',
    'gentoo base system': 'gentoo',

    'darwin': 'darwin',

    'opensuse': 'suse',
    'suse': 'suse',
}


CLI_DEFAULTS = {
    "default": CLI_DEFAULTS_DEFAULT,
    "debian": CLI_DEFAULTS_DEBIAN,
    "ubuntu": CLI_DEFAULTS_DEBIAN,
    "centos": CLI_DEFAULTS_CENTOS,
    "centos linux": CLI_DEFAULTS_CENTOS,
    "fedora": CLI_DEFAULTS_CENTOS,
    "red hat enterprise linux server": CLI_DEFAULTS_CENTOS,
    "rhel": CLI_DEFAULTS_CENTOS,
    "amazon": CLI_DEFAULTS_CENTOS,
    "amzn": CLI_DEFAULTS_CENTOS,
    "gentoo": CLI_DEFAULTS_DEFAULT,
    "gentoo base system": CLI_DEFAULTS_DEFAULT,
    "darwin": CLI_DEFAULTS_DARWIN,
    "opensuse": CLI_DEFAULTS_DEFAULT,
    "suse": CLI_DEFAULTS_DEFAULT,
}
"""CLI defaults."""


# Start system
START_INITD = 'init.d'
START_SYSTEMD = 'systemd'

# Pkg manager
PKG_YUM = 'yum'
PKG_APT = 'apt-get'

FAMILY_REDHAT = 'redhat'
FAMILY_DEBIAN = 'debian'

# redhat / debian
YUMS = ['redhat', 'fedora', 'centos', 'rhel', 'amzn', 'amazon']
DEBS = ['debian', 'ubuntu', 'kali']


class OSInfo(object):
    """OS information, name, version, like - similarity"""
    def __init__(self, name=None, version=None, version_major=None, like=None, family=None,
                 packager=None, start_system=None, has_os_release=False, fallback_detection=False, long_name=None,
                 *args, **kwargs):
        self.name = name
        self.long_name = long_name
        self.version_major = version_major
        self.version = version
        self.like = like
        self.family = family

        self.packager = packager
        self.start_system = start_system

        self.has_os_release = has_os_release
        self.fallback_detection = fallback_detection

    def to_json(self):
        """
        Converts to the JSON
        :return:
        """
        js = collections.OrderedDict()
        js['name'] = self.name
        js['long_name'] = self.long_name
        js['version_major'] = self.version_major
        js['version'] = self.version
        js['like'] = self.like
        js['family'] = self.family
        js['packager'] = self.packager
        js['start_system'] = self.start_system
        js['has_os_release'] = self.has_os_release
        js['fallback_detection'] = self.fallback_detection
        return js


def get_os():
    """
    Returns basic information about the OS.
    :return: OSInfo
    """

    # At first - parse os-release
    ros = OSInfo()

    os_release_path = '/etc/os-release'
    if os.path.isfile(os_release_path):
        ros.name = _get_systemd_os_release_var("ID", filepath=os_release_path)
        ros.version = _get_systemd_os_release_var("VERSION_ID", filepath=os_release_path)
        ros.like = _get_systemd_os_release_var("ID_LIKE", os_release_path).split(" ")
        ros.long_name = _get_systemd_os_release_var("PRETTY_NAME", filepath=os_release_path)
        ros.has_os_release = True
        if not ros.long_name:
            ros.long_name = _get_systemd_os_release_var("NAME", filepath=os_release_path)

    # Try /etc/redhat-release and /etc/debian_version
    if not ros.has_os_release or ros.like is None or ros.version is None or ros.name is None:
        os_redhat_release(ros)
        os_debian_version(ros)
        os_issue(ros)

    # like detection
    os_like_detect(ros)
    os_family_detect(ros)

    # Major version
    os_major_version(ros)

    # Packager detection - yum / apt-get
    os_packager(ros)

    # Start system - init.d / systemd
    os_start_system(ros)

    return ros


def os_family_detect(ros):
    """
    OS Family (redhat, debian, ...)
    :param ros:
    :return:
    """
    if util.startswith(ros.like, YUMS):
        ros.family = FAMILY_REDHAT
    if util.startswith(ros.like, DEBS):
        ros.family = FAMILY_DEBIAN

    if ros.family is not None:
        if sum([1 for x in YUMS if ros.name.lower().startswith(x)]) > 0:
            ros.family = FAMILY_REDHAT
        if sum([1 for x in DEBS if ros.name.lower().startswith(x)]) > 0:
            ros.family = FAMILY_DEBIAN
        return


def os_packager(ros):
    if ros.like is not None:
        if util.startswith(ros.like, YUMS):
            ros.packager = PKG_YUM
        if util.startswith(ros.like, DEBS):
            ros.packager = PKG_APT
        return ros

    if ros.name is not None:
        if sum([1 for x in YUMS if ros.name.lower().startswith(x)]) > 0:
            ros.packager = PKG_YUM
        if sum([1 for x in DEBS if ros.name.lower().startswith(x)]) > 0:
            ros.packager = PKG_APT
        return

    if os.path.exists('/etc/yum'):
        ros.packager = PKG_YUM

    if os.path.exists('/etc/apt/sources.list'):
        ros.packager = PKG_APT


def os_start_system(ros):
    if os.path.exists('/etc/systemd'):
        ros.start_system = START_SYSTEMD
    else:
        ros.start_system = START_INITD
    return ros


def os_issue(ros):
    if os.path.exists('/etc/issue'):
        with open('/etc/issue', 'r') as fh:
            issue = fh.readline().strip()
            issue = re.sub(r'\\[a-z]', '', issue).strip()

            match1 = re.match(r'^(.+?)\s+release\s+(.+?)$', issue, re.IGNORECASE)
            match2 = re.match(r'^(.+?)\s+([0-9.]+)\s*(LTS)?$', issue, re.IGNORECASE)
            if match1:
                ros.long_name = match1.group(1).strip()
                ros.version = match1.group(2).strip()
            elif match2:
                ros.long_name = match2.group(1).strip()
                ros.version = match2.group(2).strip()
            else:
                ros.long_name = issue
    return ros


def os_debian_version(ros):
    if os.path.exists('/etc/debian_version'):
        with open('/etc/debian_version', 'r') as fh:
            debver = fh.readline().strip()
            ros.like = 'debian'
            ros.family = FAMILY_DEBIAN
            if ros.version is None:
                ros.version = debver.strip()
    return ros


def os_redhat_release(ros):
    if os.path.exists('/etc/redhat-release'):
        with open('/etc/redhat-release', 'r') as fh:
            redhatrel = fh.readline().strip()
            ros.like = 'redhat'
            ros.family = FAMILY_REDHAT
            match = re.match(r'^(.+?)\s+release\s+(.+?)$', redhatrel, re.IGNORECASE)
            if match is not None:
                ros.long_name = match.group(1).strip()
                ros.version = match.group(2).strip()
            else:
                ros.long_name = redhatrel
    return ros


def os_like_detect(ros):
    if not ros.like and ros.name is not None:
        try:
            ros.like = FLAVORS[ros.name.lower()]
        except:
            pass

    if not ros.like and ros.long_name is not None:
        try:
            ros.like = FLAVORS[ros.long_name.lower()]
        except:
            pass

    return ros


def os_major_version(ros):
    if ros.version is not None:
        match = re.match(r'(.+?)[/.]', ros.version)
        if match:
            ros.version_major = match.group(1)
    return ros


def get_os_info(filepath="/etc/os-release"):
    """
    Get OS name and version

    :param str filepath: File path of os-release file
    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """

    if os.path.isfile(filepath):
        # Systemd os-release parsing might be viable
        os_name, os_version = get_systemd_os_info(filepath=filepath)
        if os_name:
            return (os_name, os_version)

    # Fallback to platform module
    return get_python_os_info()


def get_os_info_ua(filepath="/etc/os-release"):
    """
    Get OS name and version string for User Agent

    :param str filepath: File path of os-release file
    :returns: os_ua
    :rtype: `str`
    """

    if os.path.isfile(filepath):
        os_ua = _get_systemd_os_release_var("PRETTY_NAME", filepath=filepath)
        if not os_ua:
            os_ua = _get_systemd_os_release_var("NAME", filepath=filepath)
        if os_ua:
            return os_ua

    # Fallback
    return " ".join(get_python_os_info())


def get_systemd_os_info(filepath="/etc/os-release"):
    """
    Parse systemd /etc/os-release for distribution information

    :param str filepath: File path of os-release file
    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """

    os_name = _get_systemd_os_release_var("ID", filepath=filepath)
    os_version = _get_systemd_os_release_var("VERSION_ID", filepath=filepath)

    return (os_name, os_version)


def get_systemd_os_like(filepath="/etc/os-release"):
    """
    Get a list of strings that indicate the distribution likeness to
    other distributions.

    :param str filepath: File path of os-release file
    :returns: List of distribution acronyms
    :rtype: `list` of `str`
    """

    return _get_systemd_os_release_var("ID_LIKE", filepath).split(" ")


def _get_systemd_os_release_var(varname, filepath="/etc/os-release"):
    """
    Get single value from systemd /etc/os-release

    :param str varname: Name of variable to fetch
    :param str filepath: File path of os-release file
    :returns: requested value
    :rtype: `str`
    """

    var_string = varname+"="
    if not os.path.isfile(filepath):
        return ""
    with open(filepath, 'r') as fh:
        contents = fh.readlines()

    for line in contents:
        if line.strip().startswith(var_string):
            # Return the value of var, normalized
            return normalize_string(line.strip()[len(var_string):])
    return ""


def get_python_os_info():
    """
    Get Operating System type/distribution and major version
    using python platform module

    :returns: (os_name, os_version)
    :rtype: `tuple` of `str`
    """
    info = platform.system_alias(
        platform.system(),
        platform.release(),
        platform.version()
    )
    os_type, os_ver, _ = info
    os_type = os_type.lower()
    if os_type.startswith('linux'):
        info = platform.linux_distribution()
        # On arch, platform.linux_distribution() is reportedly ('','',''),
        # so handle it defensively
        if info[0]:
            os_type = info[0]
        if info[1]:
            os_ver = info[1]
    elif os_type.startswith('darwin'):
        os_ver = subprocess.Popen(
            ["sw_vers", "-productVersion"],
            stdout=subprocess.PIPE
        ).communicate()[0].rstrip('\n')
    elif os_type.startswith('freebsd'):
        # eg "9.3-RC3-p1"
        os_ver = os_ver.partition("-")[0]
        os_ver = os_ver.partition(".")[0]
    elif platform.win32_ver()[1]:
        os_ver = platform.win32_ver()[1]
    else:
        # Cases known to fall here: Cygwin python
        os_ver = ''
    return os_type, os_ver


def os_like(key):
    """
    Tries to transform OS ID to LIKE_ID
    :param key:
    :return: string or None
    """
    try:
        return FLAVORS[key.lower()]
    except KeyError:
        return None


def os_constant(key):
    """
    Get a constant value for operating system

    :param key: name of cli constant
    :return: value of constant for active os
    """

    os_info = get_os_info()
    try:
        constants = CLI_DEFAULTS[os_info[0].lower()]
    except KeyError:
        constants = os_like_constants()
        if not constants:
            constants = CLI_DEFAULTS["default"]
    return constants[key]


def os_like_constants():
    """
    Try to get constants for distribution with
    similar layout and configuration, indicated by
    /etc/os-release variable "LIKE"

    :returns: Constants dictionary
    :rtype: `dict`
    """

    os_like = get_systemd_os_like()
    if os_like:
        for os_name in os_like:
            if os_name in CLI_DEFAULTS.keys():
                return CLI_DEFAULTS[os_name]
    return {}


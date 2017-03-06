#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals
from past.builtins import basestring

import binascii
import errno
import grp
import hashlib
import math
import hmac
import logging
import os
import pwd
import random
import re
import shutil
import socket
import stat
import string
import subprocess
import sys
import threading
import time
import types
import psutil
import requests
from audit import AuditManager
from builtins import input
from builtins import bytes

import OpenSSL
import socketserver
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from sarge import run, Capture, Feeder
from jbossply.jbossparser import JbossParser

import errors

logger = logging.getLogger(__name__)


class Port(object):
    """
    Defines a port
    """
    def __init__(self, port=None, tcp=True, service=None, *args, **kwargs):
        self.port = port
        self.tcp = tcp
        self.service = None

    def __repr__(self):
        return '%s(port=%r, tcp=%r, service=%r)' % (self.__class__, self.port, self.tcp, self.service)

    def __str__(self):
        if self.service is None:
            return '%s/%s' % ('tcp' if self.tcp else 'udp', self.port)
        else:
            return '%s/%s (%s)' % ('tcp' if self.tcp else 'udp', self.port, self.service)


def run_script(params, shell=False):
    """Run the script with the given params.

    :param list params: List of parameters to pass to Popen

    """
    try:
        proc = subprocess.Popen(params, shell=shell,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

    except (OSError, ValueError):
        msg = "Unable to run the command: %s" % " ".join(params)
        logger.error(msg)
        raise errors.SubprocessError(msg)

    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        msg = "Error while running %s.\n%s\n%s" % (
            " ".join(params), stdout, stderr)
        # Enter recovery routine...
        logger.error(msg)
        raise errors.SubprocessError(msg)

    return stdout, stderr


def exe_exists(exe):
    """Determine whether path/name refers to an executable.

    :param str exe: Executable path or name

    :returns: If exe is a valid executable
    :rtype: bool

    """
    def is_exe(path):
        """Determine if path is an exe."""
        return os.path.isfile(path) and os.access(path, os.X_OK)

    path, _ = os.path.split(exe)
    if path:
        return is_exe(exe)
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            if is_exe(os.path.join(path, exe)):
                return True

    return False


def make_or_verify_dir(directory, mode=0o755, uid=0, strict=False):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.
    :param bool strict: require directory to be owned by current user

    :raises .errors.Error: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if strict and not check_permissions(directory, mode, uid):
                raise errors.Error(
                    "%s exists, but it should be owned by user %d with"
                    "permissions %s" % (directory, uid, oct(mode)))
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param str filepath: Path to the tested file (or directory).
    :param int mode: Expected file mode.
    :param int uid: Expected file owner.

    :returns: True if `mode` and `uid` match, False otherwise.
    :rtype: bool

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def chown(path, user, group=None, follow_symlinks=False):
    """
    Changes the ownership of the path.
    :param path:
    :param user:
    :param group:
    :return:
    """
    if group is None:
        group = user

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)


def file_backup(path, chmod=0o644, backup_dir=None, backup_suffix=None):
    """
    Backup the given file by copying it to a new file
    Copy is preferred to move. Move can keep processes working with the opened file after move operation.

    :param path:
    :param chmod:
    :param backup_dir:
    :param backup_suffix: if defined, suffix is appended to the backup file (e.g., .backup)
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)
        if backup_suffix is not None:
            backup_path += backup_suffix

        if chmod is None:
            chmod = os.stat(path).st_mode & 0o777

        with open(path, 'r') as src:
            fhnd, fname = unique_file(backup_path, chmod)
            with fhnd:
                shutil.copyfileobj(src, fhnd)
                backup_path = fname
    return backup_path


def dir_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the given directory
    :param path:
    :param chmod:
    :param backup_dir:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)

        if chmod is None:
            chmod = os.stat(path).st_mode & 0777

        backup_path = safe_new_dir(backup_path, mode=chmod)
        os.rmdir(backup_path)
        shutil.copytree(path, backup_path)
    return backup_path


def delete_file_backup(path, chmod=0o644, backup_dir=None, backup_suffix=None):
    """
    Backup the current file by moving it to a new file
    :param path:
    :param chmod:
    :param backup_dir:
    :param backup_suffix: if defined, suffix is appended to the backup file (e.g., .backup)
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = file_backup(path, chmod=chmod, backup_dir=backup_dir, backup_suffix=backup_suffix)
        os.remove(path)
    return backup_path


def safe_create_with_backup(path, mode='w', chmod=0o644, backup_dir=None, backup_suffix=None):
    """
    Safely creates a new file, backs up the old one if existed
    :param path:
    :param mode:
    :param chmod:
    :param backup_dir:
    :param backup_suffix: if defined, suffix is appended to the backup file (e.g., .backup)
    :return: file handle, backup path
    """
    backup_path = delete_file_backup(path, chmod, backup_dir=backup_dir, backup_suffix=backup_suffix)
    return safe_open(path, mode, chmod), backup_path


def safe_open(path, mode="w", chmod=None, buffering=None, exclusive=True):
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.
    :param bool exclusive: if True, the file cannot exist before
    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    if exclusive:
        flags |= os.O_EXCL

    return os.fdopen(os.open(path, flags, *open_args),mode, *fdopen_args)


def safe_open_append(path, chmod=None, buffering=None, exclusive=False):
    """Safely open a file for append. If file exists, it is

    :param str path: Path to a file.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.
    :param bool exclusive: if True, the file cannot exist before
    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if exclusive:
        flags |= os.O_EXCL

    return os.fdopen(os.open(path, flags, *open_args), 'a', *fdopen_args)


def safe_new_dir(path, mode=0o755):
    """
    Creates a new unique directory. If the given directory already exists,
    linear incrementation is used to create a new one.


    :param path:
    :param mode:
    :return:
    """
    path, tail = os.path.split(path)
    return _unique_dir(
        path, dirname_pat=(lambda count: "%s_%04d" % (tail, count)),
        count=0, mode=mode)


def _unique_dir(path, dirname_pat, count, mode):
    while True:
        current_path = os.path.join(path, dirname_pat(count))
        try:
            os.makedirs(current_path, mode)
            return os.path.abspath(current_path)

        except OSError as exception:
            # "Dir exists," is okay, try a different name.
            if exception.errno != errno.EEXIST:
                raise
        count += 1


def _unique_file(path, filename_pat, count, mode):
    while True:
        current_path = os.path.join(path, filename_pat(count))
        try:
            return safe_open(current_path, chmod=mode),\
                os.path.abspath(current_path)
        except OSError as err:
            # "File exists," is okay, try a different name.
            if err.errno != errno.EEXIST:
                raise
        count += 1


def unique_file(path, mode=0o777):
    """Safely finds a unique file.

    :param str path: path/filename.ext
    :param int mode: File mode

    :returns: tuple of file object and file name

    """
    path, tail = os.path.split(path)
    filename, extension = os.path.splitext(tail)
    return _unique_file(
        path, filename_pat=(lambda count: "%s_%04d%s" % (filename, count, extension if not None else '')),
        count=0, mode=mode)


def unique_lineage_name(path, filename, mode=0o777):
    """Safely finds a unique file using lineage convention.

    :param str path: directory path
    :param str filename: proposed filename
    :param int mode: file mode

    :returns: tuple of file object and file name (which may be modified
        from the requested one by appending digits to ensure uniqueness)

    :raises OSError: if writing files fails for an unanticipated reason,
        such as a full disk or a lack of permission to write to
        specified location.

    """
    preferred_path = os.path.join(path, "%s.conf" % (filename))
    try:
        return safe_open(preferred_path, chmod=mode), preferred_path
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise
    return _unique_file(
        path, filename_pat=(lambda count: "%s-%04d.conf" % (filename, count)),
        count=1, mode=mode)


def safely_remove(path):
    """Remove a file that may not exist."""
    try:
        os.remove(path)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise


def random_password(length):
    """
    Generates a random password which consists of digits, lowercase and uppercase characters
    :param length:
    :return:
    """
    return ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits + "_") for _ in range(length))


def merge(dst, src, path=None, abort_conflict=False):
    """
    Deep merges dictionary object b into a.
    :param dst:
    :param src:
    :return:
    """
    if dst is None: return None
    if src is None: return dst

    if path is None: path = []
    for key in src:
        if key in dst:
            if isinstance(dst[key], dict) and isinstance(src[key], dict):
                merge(dst[key], src[key], path + [str(key)], abort_conflict)
            elif dst[key] == src[key]:
                pass # same leaf value
            elif abort_conflict:
                raise ValueError('Conflict at %s' % '.'.join(path + [str(key)]))
            else:
                dst[key] = src[key]
        else:
            dst[key] = src[key]
    return dst


def gen_ss_cert(key, domains, not_before=None,
                validity=(7 * 24 * 60 * 60), force_san=True):
    """Generate new self-signed certificate.

    :type domains: `list` of `unicode`
    :param OpenSSL.crypto.PKey key:
    :param bool force_san:

    If more than one domain is provided, all of the domains are put into
    ``subjectAltName`` X.509 extension and first domain is set as the
    subject CN. If only one domain is provided no ``subjectAltName``
    extension is used, unless `force_san` is ``True``.

    """
    assert domains, "Must provide one or more hostnames for the cert."
    cert = OpenSSL.crypto.X509()
    cert.set_serial_number(int(binascii.hexlify(OpenSSL.rand.bytes(16)), 16))
    cert.set_version(2)

    extensions = [
        OpenSSL.crypto.X509Extension(
            b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    ]

    cert.get_subject().CN = domains[0]
    # TODO: what to put into cert.get_subject()?
    cert.set_issuer(cert.get_subject())

    if force_san or len(domains) > 1:
        extensions.append(OpenSSL.crypto.X509Extension(
            b"subjectAltName",
            critical=False,
            value=b", ".join(b"DNS:" + d.encode() for d in domains)
        ))

    cert.add_extensions(extensions)

    cert.gmtime_adj_notBefore(0 if not_before is None else not_before)
    cert.gmtime_adj_notAfter(validity)

    cert.set_pubkey(key)
    cert.sign(key, bytes(b'sha256'))
    return cert


def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_x509(data, backend=None):
    backend = get_backend(backend)
    return load_pem_x509_certificate(data, backend)


def load_pem_private_key(data, password=None, backend=None):
    return serialization.load_pem_private_key(data, None, get_backend(backend))


def load_pem_private_key_pycrypto(data, password=None):
    return RSA.importKey(data, passphrase=password)


class SargeLogFilter(logging.Filter):
    """Filters out debugging logs generated by sarge - output capture. It is way too verbose for debug"""
    def __init__(self, name='', *args, **kwargs):
        self.namex = name
        logging.Filter.__init__(self, *args, **kwargs)

    def filter(self, record):
        if record.levelno != logging.DEBUG:
            return 1

        try:
            # Parse messages are too verbose, skip.
            if record.name == 'sarge.parse':
                return 0

            # Disable output processing message - length of one character.
            msg = record.getMessage()
            if 'queued chunk of length 1' in msg:
                return 0

            return 1

        except Exception as e:
            logger.error('Exception in log filtering: %s' % e)

        return 1


def cli_cmd_sync(cmd, log_obj=None, write_dots=False, on_out=None, on_err=None, cwd=None, shell=True):
    """
    Runs command line task synchronously
    :return: return code, out_acc, err_acc
    """
    # TODO: audit

    feeder = Feeder()
    p = run(cmd,
            input=feeder, async=True,
            stdout=Capture(buffer_size=1),
            stderr=Capture(buffer_size=1),
            cwd=cwd,
            shell=shell)

    out_acc = []
    err_acc = []
    ret_code = 1
    log = None
    close_log = False

    # Logging - either filename or logger itself
    if log_obj is not None:
        if isinstance(log_obj, types.StringTypes):
            delete_file_backup(log_obj, chmod=0o600)
            log = safe_open(log_obj, mode='w', chmod=0o600)
            close_log = True
        else:
            log = log_obj

    try:
        while len(p.commands) == 0:
            time.sleep(0.15)

        while p.commands[0].returncode is None:
            out = p.stdout.readline()
            err = p.stderr.readline()

            # If output - react on input challenges
            if out is not None and len(out) > 0:
                out_acc.append(out)

                if log is not None:
                    log.write(out)
                    log.flush()

                if write_dots:
                    sys.stderr.write('.')

                if on_out is not None:
                    on_out(out, feeder, p)

            # Collect error
            if err is not None and len(err) > 0:
                err_acc.append(err)

                if log is not None:
                    log.write(err)
                    log.flush()

                if write_dots:
                    sys.stderr.write('.')

                if on_err is not None:
                    on_err(err, feeder, p)

            p.commands[0].poll()
            time.sleep(0.01)

        ret_code = p.commands[0].returncode

        # Collect output to accumulator
        rest_out = p.stdout.readlines()
        if rest_out is not None and len(rest_out) > 0:
            for out in rest_out:
                out_acc.append(out)
                if log is not None:
                    log.write(out)
                    log.flush()
                if on_out is not None:
                    on_out(out, feeder, p)

        # Collect error to accumulator
        rest_err = p.stderr.readlines()
        if rest_err is not None and len(rest_err) > 0:
            for err in rest_err:
                err_acc.append(err)
                if log is not None:
                    log.write(err)
                    log.flush()
                if on_err is not None:
                    on_err(err, feeder, p)

        return ret_code, out_acc, err_acc

    finally:
        feeder.close()
        if close_log:
            log.close()


def get_file_mtime(file):
    return os.path.getmtime(file)


def normalize_string(orig):
    """
    Helper function for _get_systemd_os_release_var() to remove quotes
    and whitespaces around the string (strip/trim)
    """
    return orig.replace('"', '').replace("'", "").strip()


# Just make sure we don't get pwned... Make sure that it also doesn't
# start with a period or have two consecutive periods <- this needs to
# be done in addition to the regex
EMAIL_REGEX = re.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+$")


def safe_email(email):
    """Scrub email address before using it."""
    if EMAIL_REGEX.match(email) is not None:
        return not email.startswith(".") and ".." not in email
    else:
        logger.warning("Invalid email address: %s.", email)
        return False


def get_utc_sec():
    return time.time()


def silent_close(c):
    try:
        if c is not None:
            c.close()
    except:
        pass


def hmac_obj(key, data):
    return hmac.new(key, data, hashlib.sha256)


def test_port_open(host='127.0.0.1', port=80, timeout=15, attempts=3, test_upper_read_write=True, tcp=True,
                   test_write_read=False, test_write=False):
    """
    Test if the given port is open on the TCP/UDP.

    :param host: host to connect to
    :param port: port to connect to
    :param attempts: number of attempts before failing test
    :param timeout: timeout in seconds
    :param test_upper_read_write: if True (default) the echo uppercase is tested - our port tester. Otherwise
        the test is successful if socket reads something.
    :param tcp: if True, TCP is tested, if false, UDP
    :param test_write_read: if True, socket is written / read
    :param test_write: if True, socket is written
    :return:
    """
    idx = 0
    while idx < attempts:
        sock = None
        try:
            if tcp:
                sock = socket.create_connection((host, port), timeout=timeout)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)

            # read/write test on the dummy server - our.
            if test_upper_read_write or test_write_read or test_write:
                random_nonce = 'ebstall-letsencrypt-test-' + (random_password(32).lower())

                if tcp:
                    sock.sendall(random_nonce)
                else:
                    sock.sendto(random_nonce, (host, port))

                read_data = None
                if test_upper_read_write or test_write_read:
                    read_data = sock.recv(4096)

                if test_upper_read_write:
                    if read_data is None or len(read_data) == 0:
                        raise ValueError('Data read from the socket is empty')
                    if read_data.strip() != random_nonce.upper().strip():
                        raise ValueError('Data read from the socket do not match the expectations')

            silent_close(sock)
            sock = None
            return True

        except:
            time.sleep(1)
            pass

        finally:
            idx += 1
            silent_close(sock)

    return False


def is_port_listening(port, tcp=True):
    """
    Returns a connection if the given port is listening, None otherwise
    :param port:
    :param tcp:
    :return:
    """
    conns = psutil.net_connections('tcp' if tcp else 'udp')
    for con in conns:
        if con.laddr[1] == port and (not tcp or (con.status is not None and con.status.upper() == 'LISTEN')):
            return con
    return None


def defval(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if val is not None else default


def defvalkey(js, key, default=None, take_none=True):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if key not in js:
        return default
    if js[key] is None and not take_none:
        return default
    return js[key]


def strip(x):
    """
    Strips string x (if non empty) or each string in x if it is a list
    :param x:
    :return:
    """
    if x is None:
        return None
    if isinstance(x, types.ListType):
        return [y.strip() if y is not None else y for y in x]
    else:
        return x.strip()


def is_empty(x):
    """
    Returns true if object is empty or none
    :param x:
    :return:
    """
    if x is None:
        return True
    if isinstance(x, types.ListType) \
            or isinstance(x, types.DictType) \
            or isinstance(x, types.TupleType) \
            or isinstance(x, set) \
            or isinstance(x, basestring):
        return len(x) == 0
    raise ValueError('Unknown type for %s' % x)


def startswith(x, testz):
    """
    Returns true if x or any element in x (if list) matches testz or any element in testz (if list)
    :param x:
    :param testz:
    :return:
    """
    if not isinstance(x, types.ListType):
        x = [x]
    if not isinstance(testz, types.ListType):
        testz = [testz]
    for sx in x:
        for test in testz:
            if sx is not None and sx.startswith(test):
                return True
    return False


def equals_any(subject, target):
    """
    Returns true if subject (or any of the subjects if list) equals to the target (or any of the targets if list)
    :param subject:
    :param target:
    :return:
    """
    if not isinstance(subject, types.ListType):
        subject = [subject]
    if not isinstance(target, types.ListType):
        target = [target]
    for sub in subject:
        for tgt in target:
            if sub == tgt:
                return True
    return False


def escape_shell(inp):
    """
    Shell-escapes input param
    :param inp:
    :return:
    """
    try:
        import shellescape
        return shellescape.quote(inp)
    except:
        pass

    try:  # py3
        from shlex import quote
    except ImportError:  # py2
        from pipes import quote
    return quote(inp)


def py_raw_input(question=None):
    """
    Python compatibility wrapper for standard raw_input()
    :param question:
    :return:
    """
    return input(question)


def net_size_to_mask(bits):
    """
    Converts network size in bits to the network mask
    e.g., 24 -> 255.255.255.0
    :param bits:
    :return:
    """
    segs = []
    for i in range(0, 4):
        sub = 8 if bits >= 8 else bits
        bits -= 8 if bits >= 8 else sub
        segs.append((((2**sub) - 1) << (8-sub)))
    return '.'.join(['%d' % x for x in segs])


def get_leftmost_domain(hostname):
    """
    Extracts leftmost domain from the hostname
    :param hostname:
    :return:
    """
    if hostname is None:
        return None
    parts = hostname.split('.', 1)
    return parts[0]


class EchoUpTCPHandler(socketserver.BaseRequestHandler):
    """Handler for a dummy socket server for firewall testing"""
    def handle(self):
        try:
            read_data = self.request.recv(1024).strip()
            if read_data is not None and len(read_data) > 0:
                self.request.sendall(read_data.upper())
        except:
            pass

    pass


class EchoUpUDPHandler(socketserver.BaseRequestHandler):
    """Handler for a dummy socket server for firewall testing"""
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        socket.sendto(data.upper(), self.client_address)


class EchoUpServer(object):
    """
    Echo uppercase base server bound on the specific socket.
    Server is started in a new thread so it does not block.
    """
    def __init__(self, address):
        self.address = address
        self.thread = None

    def start(self):
        """
        Starts the server in the separate thread (async)
        :return:
        """
        self.server.allow_reuse_address = True
        self.server.server_bind()     # Manually bind, to support allow_reuse_address
        self.server.server_activate()

        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.setDaemon(True)
        self.thread.start()
        return self

    def close(self):
        """
        Shuts down the server
        :return:
        """
        try:
            self.server.shutdown()
            self.server.server_close()
        except:
            pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class EchoUpTCPServer(EchoUpServer):
    """
    Echo upper case TCP server
    """
    def __init__(self, address):
        EchoUpServer.__init__(self, address)
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer(self.address, EchoUpTCPHandler, False)


class EchoUpUDPServer(EchoUpServer):
    """
    Echo upper case UDP server
    """
    def __init__(self, address):
        EchoUpServer.__init__(self, address)
        socketserver.UDPServer.allow_reuse_address = True
        self.server = socketserver.UDPServer(self.address, EchoUpUDPHandler, False)


def test_port_open_with_server(bind='0.0.0.0', host='127.0.0.1', port=80, timeout=15, attempts=3, tcp=True):
    """
    Test if the given port is open on the TCP.
    Starts the dummy serer for the time of the test.

    :param bind: address to bind server to
    :param host: host to connect to
    :param port: port to connect to
    :param attempts: number of attempts before failing test
    :param timeout: timeout in seconds
    :param tcp: if True, TCP is tested, if false, UDP
    :return:
    """

    server = None
    if tcp:
        server = EchoUpTCPServer((bind, port))
    else:
        server = EchoUpUDPServer((bind, port))

    with server.start():
        time.sleep(1.5)
        return test_port_open(host=host, port=port, timeout=timeout, attempts=attempts,
                              test_upper_read_write=True, tcp=tcp)
    pass


def test_port_routable(host='127.0.0.1', port=80, tcp=True, with_server=True, bind='0.0.0.0',
                       timeout=7, attempts=3, audit=None):
    """
    Testing if EJBCA port is routable from the public IP address.
    If server is True the echo server is spawned on the local server
    :param host:
    :param port:
    :param tcp:
    :param with_server: if true, the local server is bound to the socket to test the routability
    :param bind: address to bind local server to
    :param timeout:
    :param attempts:
    :param audit: Auditing module
    :return: True if routable, false if not, None if cannot determine
    """
    if audit is None:
        audit = AuditManager(disabled=True)

    # Is listening? If yes, test directly
    is_listening = is_port_listening(port=port, tcp=tcp)
    audit.audit_evt('port-listening', port=port, host=host, tcp=tcp, with_server=with_server, bind=bind,
                    is_listening=is_listening)

    if is_listening:
        # For UDP we just don't know :/
        if not tcp:
            return None

        is_open = test_port_open(host=host, port=port, timeout=timeout, attempts=attempts, tcp=tcp,
                                 test_upper_read_write=False)
        audit.audit_evt('port-open', port=port, host=host, tcp=tcp, with_server=with_server, attempts=attempts,
                        is_open=is_open)
        return is_open

    # Not listening - try anyway, listening detection may malfunction
    if tcp:
        is_open = test_port_open(host=host, port=port, timeout=timeout, attempts=attempts, tcp=tcp,
                                 test_upper_read_write=False)
        audit.audit_evt('port-open', port=port, host=host, tcp=tcp, with_server=with_server, attempts=attempts,
                        is_open=is_open)
        if is_open:
            return True

    if not with_server:
        return None

    # Read / write socket is not tried - does not work for UDPs.
    succ2 = False
    try:
        succ2 = test_port_open_with_server(host=host, port=port, tcp=tcp, timeout=timeout)
    except:
        pass

    audit.audit_evt('port-open-echo', port=port, host=host, tcp=tcp, attempts=attempts, timeout=timeout,
                    is_open=succ2)
    return succ2


def jboss_to_json(output):
    """
    Converts jboss CLI output to JSON
    :param output:
    :return:
    """
    if isinstance(output, types.ListType):
        output = ''.join(output)
    parser = JbossParser()
    return parser.parse(output)


def sha1(input, as_hex=False):
    """
    Returns sha1(
    :param input:
    :return: sha1(input)
    """
    m = hashlib.sha1()
    m.update(input)
    if as_hex:
        return m.hexdigest()
    else:
        return m.digest()


def collision_generator(src, prefix_len=20, nonce_init=1):
    """
    Simple SHA prefix collision generator.
    Returns a nonce such that SHA1(src+nonce) = 00000....
    where length of the zeros is prefix_len in bytes.

    :param src:
    :param prefix_len:
    :param nonce_init:
    :return:
    """
    nonce = nonce_init
    prefix_len_4 = int(math.ceil(prefix_len / float(4)))
    prefix_len_4_zero = '0' * prefix_len_4
    prefix_len_is_mod = prefix_len % 4 == 0

    prefix_len_bytes = int(math.ceil(prefix_len / float(8)))
    prefix_len_mod_8 = prefix_len % 8
    prefix_last_byte = (2**prefix_len_mod_8 - 1) << (8 - prefix_len_mod_8)

    while True:
        m = hashlib.sha1()
        m.update(src + str(nonce))

        if prefix_len_is_mod:
            hx = m.hexdigest()
            if hx[0:prefix_len_4] == prefix_len_4_zero:
                return nonce
        else:
            dg = m.digest()
            dgb = bytes(dg)
            for c_byte in range(prefix_len_bytes):
                if c_byte + 1 == prefix_len_bytes:
                    if int(dgb[c_byte]) & prefix_last_byte == prefix_last_byte:
                        return nonce
                elif int(dgb[c_byte]) != 0:
                    break
        nonce += 1


def determine_public_ip(attempts=3, audit=None):
    """
    Tries to determine public IP address by querying IPfy interface.
    :return: IP address or None if detection was not successful.
    """
    url = 'https://api.ipify.org?format=json'
    for attempt in range(attempts):
        try:
            if audit is not None:
                audit.audit_evt('ipify-load')

            res = requests.get(url=url, timeout=15)
            res.raise_for_status()
            js = res.json()

            if audit is not None:
                audit.audit_evt('ipify-loaded', response=js)

            return js['ip']

        except Exception as e:
            logger.debug('Exception in obtaining IP address: %s' % e)
            if audit is not None:
                audit.audit_exception(e, process='ipify')

    return None


def determine_public_ip_eb(attempts=3, audit=None, host='hut6.enigmabridge.com'):
    """
    Tries to determine public IP address by querying EB interface.
    :return: IP address or None if detection was not successful.
    """
    url = 'https://%s:8445/api/v1/apikey' % host
    headers = {'X-Auth-Token': 'public'}

    for attempt in range(attempts):
        try:
            body = {
                'nonce': random_password(8),
                'version': 1,
                'function': 'clientip'
            }

            if audit is not None:
                audit.audit_evt('eb-ip-load')

            res = requests.post(url=url, json=body, headers=headers, timeout=15)
            res.raise_for_status()
            js = res.json()

            if audit is not None:
                audit.audit_evt('eb-ip-loaded', response=js)

            resp = js['response']
            ipv4 = resp['ipv4']
            ipv6 = resp['ipv6']
            if ipv4 is not None:
                return ipv4
            if ipv6 is not None:
                return ipv6

            raise ValueError('No IP returned')

        except Exception as e:
            logger.debug('Exception in obtaining IP address: %s' % e)
            if audit is not None:
                audit.audit_exception(e, process='eb-ip')

    return None



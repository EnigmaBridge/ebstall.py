import argparse
import collections
import distutils.version  # pylint: disable=import-error,no-name-in-module
import errno
import logging
import os
import platform
import re
import six
import socket
import stat
import subprocess
import sys
import errors
import shutil
import random
import string
import pwd
import grp
import OpenSSL
import binascii
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from cryptography.x509.base import load_pem_x509_certificate
from sarge import run, Capture, Feeder
from datetime import datetime
import time
import types
import socketserver
import threading
import hashlib
import hmac


logger = logging.getLogger(__name__)


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


def file_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the given file by copying it to a new file
    Copy is preferred to move. Move can keep processes working with the opened file after move operation.

    :param path:
    :param mode:
    :param chmod:
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


def delete_file_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the current file by moving it to a new file
    :param path:
    :param mode:
    :param chmod:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = file_backup(path, chmod=chmod, backup_dir=backup_dir)
        os.remove(path)
    return backup_path


def safe_create_with_backup(path, mode='w', chmod=0o644):
    """
    Safely creates a new file, backs up the old one if existed
    :param path:
    :param mode:
    :param chmod:
    :return:
    """
    backup_path = delete_file_backup(path, chmod)
    return safe_open(path, mode, chmod), backup_path


def safe_open(path, mode="w", chmod=None, buffering=None):
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.

    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    return os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, *open_args),
        mode, *fdopen_args)


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
    cert.sign(key, "sha256")
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


def cli_cmd_sync(cmd, log_obj=None, write_dots=False, on_out=None, on_err=None, cwd=None):
    """
    Runs command line task synchronously
    :return:
    """
    feeder = Feeder()
    p = run(cmd,
            input=feeder, async=True,
            stdout=Capture(buffer_size=1),
            stderr=Capture(buffer_size=1),
            cwd=cwd)

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
            return _normalize_string(line.strip()[len(var_string):])
    return ""


def _normalize_string(orig):
    """
    Helper function for _get_systemd_os_release_var() to remove quotes
    and whitespaces around the string (strip/trim)
    """
    return orig.replace('"', '').replace("'", "").strip()


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


def test_port_open(host='127.0.0.1', port=80, timeout=15, attempts=3, test_upper_read_write=True):
    """
    Test if the given port is open on the TCP.

    :param host:
    :param port:
    :param attempts:
    :param timeout:
    :return:
    """
    idx = 0
    while idx < attempts:
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)

            # read/write test on the dummy server - our.
            if test_upper_read_write:
                random_nonce = 'ebaws-letsencrypt-test-' + (random_password(32).lower())

                sock.sendall(random_nonce)
                read_data = sock.recv(4096)
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


class DummyTCPHandler(socketserver.BaseRequestHandler):
    """Handler for a dummy socket server for firewall testing"""
    def handle(self):
        try:
            read_data = self.request.recv(1024).strip()
            if read_data is not None and len(read_data) > 0:
                self.request.sendall(read_data.upper())
        except:
            pass

    pass


class DummyTCPServer(object):
    """
    Dummy TCP server bound on the specific socket.
    Server is started in a new thread so it does not block.
    """
    def __init__(self, address):
        socketserver.TCPServer.allow_reuse_address = True
        self.address = address
        self.server = socketserver.TCPServer(self.address, DummyTCPHandler, False)
        self.thread = None

    def start(self):
        """
        Starts the server in the separate thread (async)
        :return:
        """
        self.server.allow_reuse_address = True
        self.server.server_bind()     # Manually bind, to support allow_reuse_address
        self.server.server_activate() #

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


#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import collections
from ebstall.audit import AuditManager
from ebstall import osutil
import util
import random
import errors
import logging
import shutil

"""
Basic database utils.
"""

logger = logging.getLogger(__name__)


# Database credentials loaded from the DB config file
DatabaseCredentials = collections.namedtuple('DatabaseCredentials',
                                             ['constr', 'dbtype', 'host', 'port', 'dbfile',
                                              'user', 'passwd', 'db', 'dbengine', 'data'])


def find_db_config(base_name='db.json', dirs=None):
    """
    Finds database configuration file - looks in the current working directory and project directory.
    :param base_name: database configuration name
    :param dirs: directory list to explore
    :return: path to the config file or None if the config file was not found
    """
    file_dir = os.path.dirname(os.path.realpath(__file__))
    paths = []
    if dirs is not None:
        paths += dirs
    else:
        paths = [os.getcwd(), os.path.join(file_dir, '..'), file_dir]

    for cur_dir in paths:
        cur_file = os.path.join(cur_dir, base_name)
        if os.path.exists(cur_file):
            return cur_file

    return None


def json_or_default(js, key, defval=None):
    """
    Loads key from the JS if exists, otherwise returns defval
    :param js: dictionary
    :param key: key
    :param defval: default value
    :return:
    """
    if key not in js:
        return defval
    return js[key]


def process_db_config(js):
    """
    Loads database configuration from the passed dictionary
    :param js: db config dictionary
    :return: DatabaseCredentials
    """
    dbtype = json_or_default(js, 'dbtype', 'memory').strip().lower()
    host = json_or_default(js, 'host')
    port = json_or_default(js, 'port')
    db = json_or_default(js, 'db')
    user = json_or_default(js, 'user')
    passwd = json_or_default(js, 'passwd')
    dbfile = json_or_default(js, 'dbfile')
    dbengine = json_or_default(js, 'dbengine')

    # Build connection string
    con_string = None
    if dbtype in ['mysql', 'postgresql', 'oracle', 'mssql']:
        port_str = ':%s' % port if port is not None else ''
        host_str = host if host is not None else 'localhost'
        dbengine_str = '+%s' % dbengine if dbengine is not None else ''

        if user is None or passwd is None or db is None:
            raise ValueError('User, password and database are mandatory for DB type ' + dbtype)

        con_string = '%s%s://%s:%s@%s%s/%s' % (dbtype, dbengine_str, user, passwd, host_str, port_str, db)

    elif dbtype == 'sqlite':
        if dbfile is None:
            raise ValueError('Database file (dbfile) is mandatory for SQLite database type')

        con_string = 'sqlite:///%s' % (os.path.abspath(dbfile))

    elif dbtype == 'memory':
        con_string = 'sqlite://'

    else:
        raise ValueError('Unknown database type: ' + dbtype)

    creds = DatabaseCredentials(constr=con_string, dbtype=dbtype, host=host, port=port, dbfile=dbfile,
                                user=user, passwd=passwd, db=db, dbengine=dbengine, data=js)
    return creds


class MySQL(object):
    """
    MySQL management, installation & stuff
    """

    PORT = 3306

    def __init__(self, audit=None, sysconfig=None, write_dots=False, root_passwd=None, *args, **kwargs):
        self.audit = audit if audit is not None else AuditManager(disabled=True)
        self.sysconfig = sysconfig
        self.write_dots = write_dots

        self.secure_config = None
        self.secure_query = None
        self.root_passwd = root_passwd

    def check_installed(self):
        """
        Checks if the MySQL is installed on the system
        :return: True if mysql server is installed
        """
        cmd = 'mysql --no-defaults --help >/dev/null 2>/dev/null'
        ret, out, stderr = self.sysconfig.cli_cmd_sync(cmd=cmd)
        if ret != 0:
            return False

        found, running = self.sysconfig.svc_status(self.get_svc_map())
        return found

    def check_running(self):
        """
        Returns True if the mysql server is running
        :return:
        """
        return self.sysconfig.is_port_listening(port=self.PORT, tcp=True)

    def _escape_single_quote(self, inp):
        """
        Escapes single quoted
        :param inp:
        :return:
        """
        if inp is None:
            return ''
        return inp.replace("'", "\\'")

    def _prepare_files(self, root_password=None):
        """
        Prepares configuration file.
        :return:
        """
        self.secure_config = os.path.join('/tmp', 'ebstall-sql.cnf.%s' % random.randint(0, 65535))
        util.safely_remove(self.secure_config)

        if root_password is None:
            root_password = self.root_passwd

        self.audit.add_secrets(root_password)
        with util.safe_open(self.secure_config, 'w', chmod=0o600) as fh:
            fh.write('# mysql_secure_installation config file\n')
            fh.write('[mysql]\n')
            fh.write('user=root\n')
            fh.write('password=\'%s\'\n' % self._escape_single_quote(root_password))

    def _sql_command(self, sql, root_password=None):
        """
        Executes sql command, returns return code, stdout, stderr
        Uses configuration & root password already given.
        :param sql:
        :param root_password: optional root password - another from the one set in the self
        :return: res, out, err
        """
        self._prepare_files(root_password=root_password)
        self.secure_query = os.path.join('/tmp', 'ebstall-sql.query.%s' % random.randint(0, 65535))
        with util.safe_open(self.secure_query, 'w', chmod=0o600) as fh:
            fh.write(sql)

        cmd = 'mysql --defaults-file="%s" < "%s"' % (self.secure_config, self.secure_query)
        res, out, err = self.sysconfig.cli_cmd_sync(cmd, write_dots=self.write_dots)
        self.audit.audit_sql(sql=sql, user='root', res_code=res, result=out, sensitive=True)

        util.safely_remove(self.secure_query)
        util.safely_remove(self.secure_config)
        return res, out, err

    def test_root_passwd(self, root_password=None):
        """
        Tries to test root password, returns True if valid.
        _prepare_files() has to be already called.
        :param root_password: optional root password - another from the one set in the self
        :return: returns True if password is OK
        """
        res, out, err = self._sql_command('select 1;', root_password=root_password)
        return res == 0

    #
    # Installation
    #

    def _is_maria(self):
        """
        Returns true if this OS uses maria DB by default
        :return:
        """
        os = self.sysconfig.os
        if os.name.lower() in ['centos', 'rhel'] and os.version_major >= 7:
            return True

        return False

    def get_svc_map(self):
        """
        Returns service naming for different start systems
        :return:
        """
        if self._is_maria():
            return {
                osutil.START_SYSTEMD: 'mariadb.service',
                osutil.START_INITD: 'mariadb'
            }
        else:
            return {
                osutil.START_SYSTEMD: 'mysql.service',
                osutil.START_INITD: 'mysqld'
            }

    def _get_pkg_name(self):
        """
        Returns package name for installer
        :return:
        """
        return 'mariadb-server' if self._is_maria() else 'mysql-server'

    def uninstall(self):
        """
        Removes database from the system. Used when root password is lost.
        :return:
        """
        package_name = self._get_pkg_name()

        cmd_exec = None
        if self.sysconfig.get_packager() == osutil.PKG_APT:
            cmd_exec = 'sudo apt-get remove -y %s' % package_name
        elif self.sysconfig.get_packager() == osutil.PKG_YUM:
            cmd_exec = 'sudo yum remove -y %s' % package_name
        else:
            raise OSError('Unrecognized packager')

        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dots)

    def remove_data(self):
        """
        Destructive operation, removes mysql server data.
        Has to be called only after mysql is stopped & uninstalled.
        :return:
        """
        mysql_dirs = ['/var/lib/mysql', '/var/lib/mysql-files']
        if self._is_maria():
            mysql_dirs += ['/var/lib/mariadb']

        for cur_dir in mysql_dirs:
            if not os.path.exists(cur_dir):
                continue

            backup_dir = util.safe_new_dir(cur_dir)
            shutil.move(cur_dir, backup_dir)

    def install(self, force=True):
        """
        Installs itself
        :return: installer return code
        """
        package_name = self._get_pkg_name()
        installed = False if force else self.check_installed()
        if installed:
            logger.debug('Mysql server already installed %s' % package_name)

        cmd_exec = None
        if self.sysconfig.get_packager() == osutil.PKG_APT:
            cmd_exec = 'sudo apt-get install -y %s' % package_name
        elif self.sysconfig.get_packager() == osutil.PKG_YUM:
            cmd_exec = 'sudo yum install -y %s' % package_name
        else:
            raise OSError('Unrecognized packager')

        return self.sysconfig.exec_shell(cmd_exec, write_dots=self.write_dots)

    def change_root_password(self, new_password):
        """
        Changes root password for the database. Throws an exception if the
        original password is not valid or server is not running.
        :param new_password:
        :return:
        """
        if not self.check_running():
            raise errors.EnvError('MySQL server is not running')

        if not self.test_root_passwd():
            raise errors.AccessForbiddenError('Invalid mysql root password')

        self.audit.add_secrets(new_password)
        sql = "UPDATE mysql.user SET Password=PASSWORD('%s') WHERE User='root'; FLUSH PRIVILEGES;" \
              % self._escape_single_quote(new_password)

        ret, out, err = self._sql_command(sql)
        if ret == 0:
            self.root_passwd = new_password

        if not self.test_root_passwd():
            raise errors.AccessForbiddenError('Invalid mysql root password')

        return ret

    def configure(self):
        """
        Secure configuration - like mysql_secure_installation does
        :return:
        """
        if not self.check_running():
            raise errors.EnvError('MySQL server is not running')

        self._sql_command("DELETE FROM mysql.user WHERE User='';")
        self._sql_command("DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');")
        self._sql_command("DROP DATABASE test;")
        self._sql_command("DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';")
        self._sql_command("FLUSH PRIVILEGES;")
        return 0

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




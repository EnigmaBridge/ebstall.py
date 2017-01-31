import os
import json
from core import Core
import util
from consts import *
from errors import *
from config import Config
from datetime import datetime
import shutil
import errno

__author__ = 'dusanklinec'


class SoftHsmV1Config(object):
    """
    Class for configuring SoftHSMv1 instance for EB
    """
    CONFIG_FILE = '/etc/softhsm.conf'
    CONFIG_FILE_BACKUP_DIR = '/etc/softhsm.old'
    SOFTHSM_DB_DIR = '/var/lib/softhsm'
    SOFTHSM_DB_BACKUP_DIR = '/var/lib/softhsm.old'
    SOFTHSM_SO_PATH = '/usr/lib64/softhsm/libsofthsm.so'

    DEFAULT_SLOT_CONFIG = {
            'slot': 0,
            'db': '/var/lib/softhsm/slot0.db',
            'host': 'site2.enigmabridge.com',
            'port': 11110,
            'enrollPort': 11112,
            'apikey': 'TEST_API',
            'genRSA': True,

            'retry': {
                'maxRetry': 4,
                'jitterBase': 250,
                'jitterRand': 50
            },

            'createTpl': {
                'environment': 'dev',
                'maxtps': 'one',
                'core': 'empty',
                'credit': 32000
            }
        }

    def __init__(self, config_file=CONFIG_FILE, config=None, config_template=None, *args, **kwargs):
        self.config_file = config_file
        self.json = None
        self.config = config
        self.config_template = config_template

    def config_file_exists(self):
        """
        Returns true if the SoftHSMv1 config file exists
        :return:
        """
        return os.path.isfile(self.CONFIG_FILE)

    def load_config_file(self, config_file=None):
        """
        Tries to load & parse SoftHSMv1 config file
        If file does not exist or parsing failed exception is raised

        :param config_file:
        :return:
        """
        if config_file is not None:
            self.config_file = config_file
        if self.config_file is None:
            raise ValueError('Config file is None')

        with open(self.config_file, 'r') as f:
            read_lines = [x.strip() for x in f.read().split('\n')]
            lines = []
            for line in read_lines:
                if line.startswith('//'):
                    continue
                lines.append(line)

            self.json = json.loads(lines)

    def backup_current_config_file(self):
        """
        Copies current configuration file to a new file - backup.
        softhsm.conf -> 0001_softhsm.conf

        Used when generating a new SoftHSM configuration file, to
        preserve the old one if user accidentally reinitializes the system.
        :return:
        """
        cur_name = self.CONFIG_FILE

        if os.path.exists(cur_name):
            util.make_or_verify_dir(self.CONFIG_FILE_BACKUP_DIR)
            return util.file_backup(cur_name, chmod=None, backup_dir=self.CONFIG_FILE_BACKUP_DIR)

        return None

    def configure(self, config=None):
        """
        Generates SoftHSMv1 configuration from the AMI config.
        :return:
        """
        if config is not None:
            self.config = config
        if self.config is None:
            raise ValueError('Configuration is not defined')

        slot_cfg = self.config_template if self.config_template is not None else self.DEFAULT_SLOT_CONFIG

        endpoint_process = config.resolve_endpoint(purpose=SERVER_PROCESS_DATA, protocol=PROTOCOL_RAW)[0]
        endpoint_enroll = config.resolve_endpoint(purpose=SERVER_ENROLLMENT, protocol=PROTOCOL_RAW)[0]
        if endpoint_process.host != endpoint_enroll.host:
            raise ValueError('Process host is different from the enrollment host. SoftHSM needs to be updated')

        slot_cfg['apikey'] = config.apikey
        slot_cfg['host'] = endpoint_process.host
        slot_cfg['port'] = endpoint_process.port
        slot_cfg['enrollPort'] = endpoint_enroll.port

        # Server environment?
        if 'environment' in endpoint_process.server:
            slot_cfg['createTpl']['environment'] = endpoint_process.server['environment']

        root = {'slots': [slot_cfg]}
        self.json = root
        pass

    def write_config(self):
        """
        Writes current configuration to the file.
        :return:
        """
        conf_name = self.CONFIG_FILE
        with os.fdopen(os.open(conf_name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644), 'w') as config_file:
            config_file.write('// \n')
            config_file.write('// SoftHSM configuration file for Enigma Bridge \n')
            config_file.write('// Config file generated: %s\n' % datetime.now().strftime("%Y-%m-%d %H:%M"))
            config_file.write('// \n')
            config_file.write(json.dumps(self.json, indent=2) + "\n\n")
        return conf_name

    def backup_previous_token_dir(self):
        """
        Backs up the previous token database
        :return:
        """
        if os.path.exists(self.SOFTHSM_DB_DIR):
            util.make_or_verify_dir(self.SOFTHSM_DB_BACKUP_DIR)
            backup_slot_dir = util.dir_backup(self.SOFTHSM_DB_DIR, chmod=None, backup_dir=self.SOFTHSM_DB_BACKUP_DIR)
            return backup_slot_dir

        return None

    def init_token(self, user=None):
        """
        Initializes a new SoftHSM token created by the configuration
        :param user: user to initialize token under
        :return:
        """
        util.make_or_verify_dir(self.SOFTHSM_DB_DIR, mode=0o755)
        cmd = 'softhsm --init-token --slot 0 --pin 0000 --so-pin 0000 --label ejbca'

        if user is None:
            out, err = util.run_script(cmd.split(' '))
            return out, err

        else:
            util.chown(self.SOFTHSM_DB_DIR, user, user)
            cmd_sudo = ['sudo', '-E', '-H', '-u', user, '/bin/bash', '-c', cmd]
            return util.run_script(cmd_sudo)

    def chown_tokens(self, user):
        """
        Changes the owner of the tokens
        :param user:
        :return:
        """
        if not os.path.exists(self.SOFTHSM_DB_DIR):
            return

        util.chown(self.SOFTHSM_DB_DIR, user, user)
        tokens = os.listdir(self.SOFTHSM_DB_DIR)
        for token in tokens:
            util.chown(token, user, user)

    def get_so_path(self):
        return self.SOFTHSM_SO_PATH


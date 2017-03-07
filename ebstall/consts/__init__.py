#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'dusanklinec'
CONFIG_DIR = '/etc/enigma'
CONFIG_DIR_OLD = '/etc/enigma.old'
CONFIG_FILE = 'config.json'
IDENTITY_KEY = 'key.pem'
IDENTITY_CRT = 'crt.pem'
IDENTITY_NONCE = 'nonce.data'

SERVER_PROCESS_DATA = 'process_data'
SERVER_ENROLLMENT = 'enrollment'
SERVER_REGISTRATION = 'registration'

PROTOCOL_HTTPS = 'https'
PROTOCOL_RAW = 'tcp'

LE_VERIFY_DNS = 'dns'
LE_VERIFY_TLSSNI = 'tlssni'
LE_VERIFY_DEFAULT = LE_VERIFY_TLSSNI

EC2META_FILES = ['/opt/aws/bin/ec2-metadata']

SETTINGS_FILE = 'eb-settings.json'
SETTINGS_FOLDERS = ['/etc/enigma', '/usr/local/etc/enigma', '/opt/enigmabridge/etc/']

PROVISIONING_SERVERS = ['privatespace-deploy.enigmabridge.com']


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

ONBOOT_INIT_SCRIPT = """#!/bin/sh
### BEGIN INIT INFO
# Provides:          enigmabridge-onboot
# Required-Start:    $local_fs $network $named $time $syslog
# Required-Stop:     $local_fs $network $named $time $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       EnigmaBridge on boot
# chkconfig: - 80 20
### END INIT INFO

SCRIPT="/usr/local/bin/ebins-cli -n onboot"
RUNAS=root

PIDFILE=/var/run/enigmabridge-onboot.pid
LOGFILE=/var/log/enigmabridge-onboot.log

start() {
  if [ -f /var/run/$PIDNAME ] && kill -0 $(cat /var/run/$PIDNAME); then
    echo 'Service already running' >&2
    return 1
  fi
  echo 'Starting service...' >&2
  local CMD="$SCRIPT &> \\"$LOGFILE\\" & echo \$!"
  su -c "$CMD" $RUNAS > "$PIDFILE"
  echo 'Service started' >&2
}

stop() {
  if [ ! -f "$PIDFILE" ] || ! kill -0 $(cat "$PIDFILE"); then
    echo 'Service not running' >&2
    return 1
  fi
  echo 'Stopping service...' >&2
  kill -15 $(cat "$PIDFILE") && rm -f "$PIDFILE"
  echo 'Service stopped' >&2
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    sleep 1
    start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
esac
"""

ONBOOT_INIT_SYSTEMD_SCRIPT = """
[Unit]
Description=EnigmaBridge on boot
After=network.target iptables.service firewalld.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ebins-cli -n onboot
# ExecStop=
# ExecReload=
PIDFile=/var/run/enigmabridge-onboot.pid
User=root
Group=root
# Restart=always

[Install]
WantedBy=multi-user.target
"""


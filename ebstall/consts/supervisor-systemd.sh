[Unit]
Description=Supervisord
After=network.target iptables.service firewalld.service

[Service]
ExecStart=
# ExecStop=
# ExecReload=
PIDFile=/var/run/enigmabridge-onboot.pid
User=root
Group=root
# Restart=always

[Install]
WantedBy=multi-user.target

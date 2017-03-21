[Unit]
Description=Supervisord
After=network.target iptables.service firewalld.service

[Service]
ExecStart=/usr/bin/epiper supervisord
# ExecStop=
# ExecReload=
PIDFile=/var/run/supervisord.pid
User=root
Group=root
# Restart=always

[Install]
WantedBy=multi-user.target

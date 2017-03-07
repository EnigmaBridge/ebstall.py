#!/usr/bin/env bash
cd /home/ec2-user/ebstall && pip install --upgrade --find-links=. .
/bin/cp ebstall-pki.sh /usr/sbin/ebstall-pki
/bin/cp ebstall-privspace.sh /usr/sbin/ebstall-privspace
/bin/cp ebstall.sh /usr/sbin/ebstall


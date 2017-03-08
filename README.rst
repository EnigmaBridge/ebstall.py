EnigmaBridge Installer
======================

This python installer helps with deploying `EnigmaBridge <https://enigmabridge.com>`__ products to the virtual machines.
For now we support

- EJBCA (PKI) deployment
- Private Space deployment (VPN + other services)

Features
========

-  OpenVPN
-  EJBCA 6.3.1.1 with MySQL backend
-  JBoss EAP 6.4 with LetsEncrypt HTTPS certificate
-  SoftHSMv1-EnigmaBridge PKCS#11 adapter
-  EnigmaBridge Dynamic DNS for AWS

SoftHSMv1-EnigmaBridge PKCS#11 adapter
--------------------------------------

`SoftHSMv1-EB <https://github.com/EnigmaBridge/SoftHSMv1>`__ is a
PKCS#11 interface for `EnigmaBridge <https://enigmabridge.com>`__
services. Using this adapter one can use our services using the generic
PKCS#11 interface without need to modify the software.

Like in EJBCA case, there is no need to modify the software which
supports PKCS#11, just plug our adapter to it and it starts working.

One can for example generate RSA keys via PKCS#11 adapter and call
encrypt, decrypt, sign, verify operations on it. The keys are securely
stored on EnigmaBridge servers, in the secure hardware. The
cryptographic operation itself is performed in the secure hardware in a
transparent way.

Dynamic DNS
-----------

Amazon provides IP address to your EC2 instance from the IP pool. This
kind of address is re-allocated after your instance is turned off. After
next start it will get a new IP address.

Usually its convenient to have a static IP so you can map it to the
domain name or put in the config files, manuals, etc... You can buy
Amazon Elastic IP which remains static even after instance restart or
you can use our `EnigmaBridge <https://enigmabridge.com>`__ Dynamic DNS
feature for the AWS.

During the initialization we allocate a new domains for your running
instance, e.g., sunderland1.pki.enigmabridge.com. It has A record
pointing to your current IP address.

After you restart your instance, our script is started. It connects to
our DNS server and updates the A record for your domain in a secure way
- request is signed with the key generated when domain was created.

Time to live of the record is 600 seconds so after the restart the
hostname is updated in 10 minutes.

In this way you will get the static DNS name even if your IP changes.

Requirements
============

Generally the host need to have TCP port 443 open for LetsEncrypt domain
verification. Without that you won't get valid SSL certificate for your
CA domain and you won't be able to access administration console of your
EJBCA installation in a secure way.

The EJBCA itself runs on TCP port 8443. It depends on you how you set
it. It don't necessarily have to be open to the world-fine. Its enough
if you can access it somehow. e.g., it's possible to access EJBCA admin
via SSH tunnel. ``ssh -L 8443:localhost:8443 ami_ip``

Init
====

The init command starts a new fresh installation. If a previous
installation is present it asks user whether to proceed, backups the old
installation databases and config files and installs a new one.

Updating
========
To keep the installer and packages up to date we employ several mechanisms for updating.

- Auto-updating wrapper scritps, similar principle used in Letsencrypt.

  -  Autoupdate via ``/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/EnigmaBridge/ebstall-update/master/update.sh)"``
  -  Autoupdate via ``pip install --upgrade ebstall``

- Updating EJBCA via our `deployment server <https://privatespace-deploy.enigmabridge.com/ejbca/index.json>`__

Troubleshooting
===============

Error in installation of dependencies (cryptography, pyOpenSSL):
``sorry, but this version only supports 100 named groups``
[`100-named-groups <https://community.letsencrypt.org/t/certbot-auto-fails-while-setting-up-virtual-environment-complains-about-package-hashes/20529/18>`__]

Solution: Install downgraded version of pycparser and pyOpenSSL:

::

    pip install pycparser==2.13
    pip install pyOpenSSL==0.13
    pip install cryptography

You may need to install some deps for the python packages

::

    yum install gcc g++ openssl-devel libffi-devel dialog

SNI on Python < 2.7.9
---------------------

TLS SNI support was added to Python. For earlier versions SNI needs to
be added to Requests networking library.

::

    pip install urllib3
    pip install pyopenssl
    pip install ndg-httpsclient
    pip install pyasn1

Mac OSX installation
--------------------

For new OSX versions (El Capitan and above) the default system python
installation cannot be modified with standard means. There are some
workarounds, but one can also use ``--user`` switch for pip.

::

    pip install --user cryptography

PIP update appdirs error
------------------------

Pip may have a problem with updating appdirs due to missing directory. It helps to update this package manually

::

    pip install --upgrade --no-cache appdirs


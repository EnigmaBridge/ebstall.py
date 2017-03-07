#!/bin/bash

#
# Builds EJBCA revision tarbal for deployment.
#

HOST=pprov
EJBCA_VER=ejbca_6_3_1_1
REV=${EJBCA_VER}_r1
DEST=/tmp/${EJBCA_VER}
EJBCA_SRC=/Volumes/EXTDATA/workspace/ejbca_ce_6_3_1_1/

rsync -av --rsync-path="sudo rsync" --stats --delete \
    --exclude='conf/*.properties' --exclude='.git' --exclude='*.class' --exclude='*.swp' --exclude='*~' \
    --exclude='.DS_Store' --exclude='.idea' --exclude='.pc' --exclude='.settings' \
    --include='conf/extendedkeyusage.properties' \
    ${EJBCA_SRC} ${HOST}:${DEST} \

read -d '' EJBCA_PROP << EOMSTR
appserver.home=/opt/jboss-eap-6.4.0
appserver.type=JBoss EAP 6.2
EOMSTR

echo -e "$EJBCA_PROP" | ssh ${HOST} "cat | sudo tee ${DEST}/conf/ejbca.properties"

ssh ${HOST} "sudo /bin/rm -rf ${DEST}/.idea \
    && sudo /bin/rm -rf ${DEST}/.git \
    && sudo /bin/rm -rf ${DEST}/.pc \
    && sudo /bin/rm -rf ${DEST}/.settings \
    && sudo chown jboss:jboss -R ${DEST} \
    && cd ${DEST} && sudo ant clean \
    && cd /tmp \
    && sudo chown jboss:jboss -R ${DEST} \
    && sudo /bin/rm ${REV}.tgz \
    && sudo tar -czvf ${REV}.tgz ${EJBCA_VER}"

echo -e "\n\n======================================================================"
echo "EJBCA revision deployed."
echo "In order to replace the existing revision do:"
echo "ssh ${HOST} \"sudo /bin/cp /tmp/${REV}.tgz /var/www/html/ejbca\" "


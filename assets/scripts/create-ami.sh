#!/usr/bin/env bash
#
##
## Creating S3 based AMI, EBS based AMI (EBS is below)
##
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-instance-store-ami.html
# https://robpickering.com/2010/07/create-a-full-backup-image-of-your-amazon-ec2-instance-2-129
#
# 1. Create IAM access key for the user (Access Key ID, Secret Key), required for S3 upload
#
# 2. Create RSA-2048 private key + X509 self signed certificate, upload to IAM (manage signing certificates).
#    http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/set-up-ami-tools.html#ami-tools-managing-certs
#
#    openssl genrsa 2048 > private-key.pem
#    openssl req -new -x509 -nodes -sha256 -days 365 -key private-key.pem -outform PEM -out certificate.pem
#
#    For cloudwatch, etc: PKCS8 (not needed for our case)
#    openssl pkcs8 -topk8 -nocrypt -inform PEM -in private-key.pem -out private-key-8.pem
#
#    Upload the signing certificate here: https://console.aws.amazon.com/iam/home
#    Users -> <you> -> Security Credentials tab -> Manage signing certificates button -> Upload
#
#    Copy the credentials to the AMi for image building
#    scp *.pem ami:/tmp/cert
#
# 3. scp the private key and certificate to the instance under /tmp/cert
#
#  - Optionally, if you dont have 2x $USED_SPACE of the free space on your /tmp:
#  -  - create a new volume in the EC2 Web Console to fit the whole image
#  -  - attach the volume to the instance, to /dev/xvdf1
#  -  - sudo fdisk /dev/xvdf create a new partition table (g), and a new primary partition (n)
#  -  - mkfs.ext4 /dev/xvdf1
#  -  - mount /dev/xvdf1 /mnt/build
#

#
# Export data - from your configuration file.
#
export AWS_ACC=112233445566
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key

# Export the rest - copy paste
export AMI_REGION=eu-west-1
export INSTANCE_ID=`ec2-metadata -i | cut -d ' ' -f 2`
export AMI_ID=`ec2-metadata -a | cut -d ' ' -f 2`

# 4. create image (as root)
#   Creates disk image of the instance the following command is started on (instance you want to create AMI from).
#   Image requires quite a lot of free space.
#   Size 8192 MB corresponds to the size of a newly created AWS volume with 8GiB.
#   We have to use --no-filter because ec2-bundle-vol would exclude all pem files - we cannot do that (CA roots)
#   The real file size occupied on the disk is less than total size (sum of all file sizes). Thus it fits on
#   the same drive.
#
mkdir -p /mnt/build
/bin/rm /mnt/build/image 2>/dev/null
ec2-bundle-vol -k /tmp/cert/private-key.pem -c /tmp/cert/certificate.pem -u $AWS_ACC -r x86_64 \
  -e /tmp/cert,/mnt/build,/var/swap_0000.bin \
  -d /mnt/build --partition gpt --size 8192 --no-filter

#
# If you want only EBS-backed AMI you can skip to EBS-backed AMI description
# You can even CTRL+C volume creation once image file is completed (skip encryption, manifest creation).
# For S3 related instructions, check create-ami-s3.sh now. Otherwise continue.
#

#
# Prepare an Amazon EBS volume for your new AMI.
# Check out the size of the created image, has to be at least that large
#
VOLRES=`aws ec2 create-volume --size 8 --region $AMI_REGION --availability-zone ${AMI_REGION}a --volume-type gp2`
echo $VOLRES
sleep 5

# The command will produce a row like: "VolumeId": "vol-38fcf689", export the value to the env var.
export VOLUME_ID=`echo $VOLRES | python -c "import sys, json; print json.load(sys.stdin)['VolumeId']"`
echo $VOLUME_ID

# Attach the volume to the AMI
aws ec2 attach-volume --volume-id $VOLUME_ID --instance-id $INSTANCE_ID --device /dev/sdb --region $AMI_REGION
sleep 5

# DD-bundle to the new volume
#   We can skip ec2-download-bundle, ec2-unbundle as we have the unbundled image ready
#   If desired, use kill -SIGUSR1 DDPID to monitor DDs progress
sudo dd if=/mnt/build/image of=/dev/sdb bs=1M

# Remove unwanted fstab entries (e.g., file swaps)
# Remove SSH keys
sudo partprobe /dev/sdb
lsblk
sleep 2
sudo mkdir -p /mnt/ebs
sudo mount /dev/sdb1 /mnt/ebs

# Remove file swap entry if you have it
sudo sed -i "/\bswap\b/d" /mnt/ebs/etc/fstab

# .. run the clean script clean-aws.sh
# uninstall services, stop servers

# chroot to the image FS, delete all unnecessary data.
chroot /mnt/ebs/

# .. run the clean script clean-aws.sh
# ..
# then additional cleaning - still in chroot.
shred -u /etc/ssh/*_key /etc/ssh/*_key.pub
find /etc/ssh/ -name '*key*' -exec shred -u -z {} \;
find /root/.*history /mnt/ebs/home/*/.*history -exec shred -u -z {} \;
find / -name "authorized_keys" -exec shred -u -z {} \;
updatedb
shred -u ~/.*history
history -c

# Exit chroot: CTRL+D -
# ..

# then the final key cleanup:
sudo find /mnt/ebs/etc/ssh/ -name '*key*' -exec shred -u -z {} \;
sudo find /mnt/ebs/root/.*history /mnt/ebs/home/*/.*history -exec shred -u -z {} \;
sudo find /mnt/ebs -name "authorized_keys" -exec shred -u -z {} \;

sudo umount /mnt/ebs

# Zeroize free space
zerofree -v /dev/sdb1

# Detach EBS
aws ec2 detach-volume --volume-id $VOLUME_ID --region $AMI_REGION
sleep 5

# Create snapshot for the AMI
SNAPRES=`aws ec2 create-snapshot --region $AMI_REGION --description "EnigmaBridge-PrivateSpace" --volume-id $VOLUME_ID`
echo $SNAPRES
sleep 5

# The command will produce a row like: "SnapshotId": "snap-ef019d24", export the value to the env var.
export SNAPSHOT_ID=`echo $SNAPRES | python -c "import sys, json; print json.load(sys.stdin)['SnapshotId']"`
echo $SNAPSHOT_ID
sleep 5

# Verify snapshot - wait until the progress is 100%
aws ec2 describe-snapshots --region $AMI_REGION --snapshot-id $SNAPSHOT_ID

while :
do
    sleep 2
    export SNAPSHOT_REPORT=`aws ec2 describe-snapshots --region $AMI_REGION --snapshot-id $SNAPSHOT_ID`
    export SNAPSTATE=`echo $SNAPSHOT_REPORT | python -c "import sys, json; print json.load(sys.stdin)['Snapshots'][0]['State']"`
    if [[ "${SNAPSTATE}" != "pending" ]]; then
        break
    fi
done

# Ring the bells so we know we are finished with the snapshot
tput bel

# Get Current AMI data - architecture, kernel id (if applicable), ramdisk id (if applicable)
# [OPTIONAL]
aws ec2 describe-images --region $AMI_REGION --image-id $AMI_ID --output text

# Create new AMI
# vx for store, vxS for public sharing
aws ec2 register-image --region $AMI_REGION --name 'EnigmaBridge-PrivateSpace-v3S' \
  --block-device-mappings DeviceName=/dev/xvda,Ebs={SnapshotId=${SNAPSHOT_ID}} \
  --description 'EnigmaBridge Private Space AMI version 3S' \
  --virtualization-type hvm --architecture x86_64 \
  --root-device-name /dev/xvda

# Delete the EBS volume
aws ec2 delete-volume --volume-id $VOLUME_ID --region $AMI_REGION







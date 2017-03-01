#!/bin/bash

#
# S3 description, S3 specific part of the create-ami.sh script.
#

# For S3 you will probably need to change the manifest:
# At first, reformat manifest
sudo cp /mnt/build/image.manifest.xml /mnt/build/image.manifest.xml.bak
sudo xmllint --format /mnt/build/image.manifest.xml.bak | sudo tee /mnt/build/image.manifest.xml

#
# Fix block_device_mapping
#  - here you can add new storage devices to the AMI
#  - fix the block mapping - xvda is not accepted by aws ec2 register-image
#    <block_device_mapping>
#      <mapping>
#        <virtual>ami</virtual>
#        <device>sda</device>
#      </mapping>
#      <mapping>
#        <virtual>root</virtual>
#        <device>/dev/sda1</device>
#      </mapping>
#    </block_device_mapping>

#
# 5. Upload to S3.
#   S3 uploading requirements:
#     a) create S3 bucket enigma-ami
#     b) be sure the user you are going to use has a permissions to work with the bucket - S3, bucket, permissions.
#     c) the user has in IAM S3 policy attached / S3FullAccess.
#
ec2-upload-bundle -b enigma-ami/ejbca/ejbcav1 -m /mnt/build/image.manifest.xml --region us-east-1 \
  -a $AWS_ACCESS_KEY_ID -s $AWS_SECRET_ACCESS_KEY

#
# 6. Register AMI
#   This can be done also from your local PC.
#   If you don't have aws:
#      pip install --upgrade awscli
#      pip install --upgrade --user awscli (for Mac users)
#        For Mac aws is located: /Library/Python/2.7/bin/aws
#
aws ec2 register-image --image-location enigma-ami/ejbca/ejbcav1/image.manifest.xml --name 'EnigmaBridge-EJBCA' \
  --virtualization-type hvm --region us-east-1 \
  --description 'EnigmaBridge integrated EJBCA AMI'

#
# ----------------------------------------------------------------------------------------------------------------------
#

#
# Conversion to EBS-backed AMI
# http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_ConvertingS3toEBS.html


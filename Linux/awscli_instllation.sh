apt-get update
apt-get upgrade
apt-get install python-pip
#  https://docs.aws.amazon.com/cli/latest/userguide/awscli-install-bundle.html
#  https://docs.aws.amazon.com/cli/latest/userguide/awscli-install-linux.html

curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
unzip awscli-bundle.zip
sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
#!/bin/sh

SOURCE="$0"
while [ -h "$SOURCE"  ]; do
	DIR="$( cd -P "$( dirname "$SOURCE"  )" && pwd  )"
	SOURCE="$(readlink "$SOURCE")"
	[[ $SOURCE != /*  ]] && SOURCE="$DIR/$SOURCE"
done
SRC_PATH="$( cd -P "$( dirname "$SOURCE"  )" && pwd  )"
cd $SRC_PATH

uid=`id -u`
if [ $uid -ne 0 ]; then
  echo "ERROR: must run as root!"
  exit 1
fi

mkdir -p /opt/weak_killer >/dev/null 2>&1
cp -rf ../* /opt/weak_killer
chmod a+x /opt/weak_killer/script/service.sh

systemctl disable weak_killer
systemctl stop weak_killer
cp weak_killer.service /etc/systemd/system
systemctl daemon-reload
systemctl enable weak_killer
systemctl start weak_killer

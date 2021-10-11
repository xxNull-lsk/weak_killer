#!/bin/sh

SOURCE="$0"
while [ -h "$SOURCE"  ]; do
	DIR="$( cd -P "$( dirname "$SOURCE"  )" && pwd  )"
	SOURCE="$(readlink "$SOURCE")"
	[[ $SOURCE != /*  ]] && SOURCE="$DIR/$SOURCE"
done
SRC_PATH="$( cd -P "$( dirname "$SOURCE"  )" && pwd  )"
cd $SRC_PATH/..

python3 main.py

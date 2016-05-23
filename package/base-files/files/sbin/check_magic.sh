#!/bin/sh

img_magic=/tmp/img_magic
upgrade_img=/tmp/upgrade.img

[ "$#" -gt 1 ] && exit 1

dd if=$1 of=$img_magic bs=8 count=1
dd if=$1 of=$upgrade_img skip=1 ibs=8 obs=1M
rm -rf $1
mv $upgrade_img $1
local magic="$(hexdump -e '1/1 "%02x"' $img_magic)"

[ "$magic" != "27051956d1c237a4" ] && {
	exit 1
}
exit 0
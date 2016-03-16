#!/bin/sh

if [ $# -ne 2 ]; then
  echo "Usage: $0 path name"
  exit 1;
fi

try_times=0
interval=120
url="$1?name=$2"
down_dir="/tmp/clatdm_down"
res_dir="/www/connect/res/"
down_log="/tmp/clatdm_down.log"
des_file="$down_dir/webs.tar.gz"
not_found="404 Not Found"
down_success="100%"

[ -d "$down_dir" ] || {
	mkdir $down_dir
}

wget -O $des_file $url &> $down_log
if grep -q '404' $down_log  &&  grep -q 'Not' $down_log  ; then
	exit 0
else
	if  grep -q $down_success $down_log ; then
		if tar -zxf $des_file -C $down_dir &> /dev/null ; then
			rm -rf $des_file
			chmod 644 -R $down_dir &> /dev/null
		fi
		exit 0
	else
		sleep $interval
		{
			wget -O $des_file $url &> $down_log
			if grep -q '404' $down_log  &&  grep -q 'Not' $down_log  ; then
				exit 0
			else
				if  grep -q $down_success $down_log ; then
					if tar -zxf $des_file -C $down_dir &> /dev/null ; then
						rm -rf $des_file
						chmod 644 -R $down_dir &> /dev/null
					fi
					exit 0
				else
					exit 1
				fi
			fi
		}
	fi
fi


exit 0
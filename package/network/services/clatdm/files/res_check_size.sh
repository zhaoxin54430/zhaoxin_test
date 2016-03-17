#!/bin/sh

if [ $# -ne 1 ]; then
  echo "Usage: $0 pid"
  exit 1;
fi

down_dir="/tmp/clatdm_down"
des_file="$down_dir/webs.tar.gz"
max_size=8388608 #8M

while true;
do
	if [ -f "$des_file" ] 
	then
#echo "file is exist"
		break
	fi
	sleep 3
	process=`ps | grep -i "check_res" | grep -v 'grep' | wc -l`
	if [ $process -le 0 ]
	then
#echo "check_res 1 don't exist exit"
		exit 0
	fi
done
	
while true;
do
    file_size=$(ls -l $des_file | awk '{ print $5 }')
#echo $file_size
    if [ $file_size -gt $max_size ] 
    then
#echo "kill $1"
        killall wget
        kill -9 $1
        rm -rf $des_file
    fi
    sleep 1
	process2=`ps | grep -i "check_res" | grep -v 'grep' | wc -l`
	if [ $process2 -le 0 ]
	then
#echo "check_res 2 don't exist exit"
		exit 0
	fi
done
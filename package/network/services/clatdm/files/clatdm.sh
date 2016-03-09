#!/bin/sh /etc/rc.common

USE_PROCD=1

START=45


MTDBLOCK7="mtdblock7"
OTHER_ROOT="/www/connect/res"
OTHER_ROOT_IMG="/www/connect/other.img"
OTHER_ROOT_FLAG="/www/connect/res/other_data_file_root_dir"
OTHER_DETECT_FILE="/www/connect/res/m_o_s_f"
MTD_PARTION_NAME="/dev/mtd7"

start_service() {
	
	local mount_str
	
	mount_str=`mount | grep $MTDBLOCK7`
	[ -z "$mount_str" ] && {
	# not mount
		[ -d "$OTHER_ROOT" ] || {
			mkdir $OTHER_ROOT
		}
		mount -t jffs2 /dev/$MTDBLOCK7 $OTHER_ROOT -o rw,sync
		[ -f "$OTHER_ROOT_FLAG" ] || {
			[ -f "$OTHER_DETECT_FILE" ] || {
			#file system invalid
				umount $OTHER_ROOT
				mtd erase $MTD_PARTION_NAME
				mtd write $OTHER_ROOT_IMG $MTD_PARTION_NAME
				mount -t jffs2 /dev/$MTDBLOCK7 $OTHER_ROOT -o rw,sync
				touch $OTHER_DETECT_FILE
			}
			[ -f "$OTHER_ROOT_FLAG" ] || {
				touch $OTHER_ROOT_FLAG
			}
		}
	}
	mkdir /tmp/others_res
	
  iptables -nvL FORWARD | grep -q '#conn' || {
          iptables -I FORWARD 1 -p tcp -m connlimit --connlimit-above 128 -j DROP
  }
  
	procd_open_instance
	procd_set_param command /bin/clatdm
	procd_set_param respawn
	procd_close_instance
}



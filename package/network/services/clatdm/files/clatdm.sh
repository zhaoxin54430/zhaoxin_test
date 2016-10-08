#!/bin/sh /etc/rc.common

USE_PROCD=1

START=45


start_service() {
	
  iptables -nvL FORWARD | grep -q '#conn' || {
          iptables -I FORWARD 1 -p tcp -m connlimit --connlimit-above 128 -j DROP
  }
	
	ebtables -t filter -D FORWARD -i wlan0-1 -o wlan0 -j DROP
	ebtables -t filter -D FORWARD -i wlan0 -o wlan0-1 -j DROP
	
	ebtables -t filter -I FORWARD 1 -i wlan0-1 -o wlan0 -j DROP
	ebtables -t filter -I FORWARD 1 -i wlan0 -o wlan0-1 -j DROP
	
	procd_open_instance
	procd_set_param command /bin/clatdm
	procd_set_param respawn
	procd_close_instance
}



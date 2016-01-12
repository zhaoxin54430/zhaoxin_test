#!/bin/sh /etc/rc.common

USE_PROCD=1

START=45

start_service() {
	procd_open_instance
	procd_set_param command /bin/clatdm
	procd_set_param respawn
	procd_close_instance
}



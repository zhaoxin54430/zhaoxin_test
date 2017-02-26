#!/bin/sh /etc/rc.common

USE_PROCD=1

START=75


start_service() {

	procd_open_instance
	procd_set_param command /bin/thermalp
	procd_set_param respawn
	procd_close_instance
}



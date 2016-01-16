#ifndef __CLATDM_H
#define __CLATDM_H

#include <syslog.h>

#define CLATDM_OUTPUT_TO_SYSLOG
#define SHARE_MEM_FLAG "/tmp/sharemem_flag"

#ifdef CLATDM_OUTPUT_TO_SYSLOG
#define clatdm_error(args...) syslog(LOG_ERR, args);
#define clatdm_info(args...) syslog(LOG_INFO, args);
#else
#define clatdm_error(args...)
#define clatdm_info(args...)
#endif

#endif
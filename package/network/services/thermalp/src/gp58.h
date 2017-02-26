#ifndef __GP___58_H
#define __GP___58_H
#include "thermalp.h"
tpRet gp58_usb_open(thermalpDev *tp);
tpRet gp58_usb_close(thermalpDev *tp);
tpRet gp58_usb_write(thermalpDev *tp, payData *pData);
#endif

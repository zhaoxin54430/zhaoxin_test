#include <stdlib.h>  
#include <stdio.h>  
#include <string.h> 
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "gp58.h"

#define GP58_USB_DEV_FILE "/dev/usb/lp0"

tpRet gp58_usb_open(thermalpDev *tp)
{
    if(!tp)
        return TP_RET_PARAMETER_ERR;

    if(tp->fp)
        fclose(tp->fp);
    
    tp->fp=fopen(GP58_USB_DEV_FILE, "w");
    if(tp->fp==NULL)
        return TP_RET_ERROR;
    else
        return TP_RET_SUCCESS;
}
tpRet gp58_usb_close(thermalpDev *tp)
{
    if(!tp)
        return TP_RET_PARAMETER_ERR;

    fclose(tp->fp);
    tp->fp=NULL;
    return TP_RET_SUCCESS;
}
tpRet gp58_usb_write(thermalpDev *tp, payData *pData)
{
    int i, de_len;
    unsigned char buf[64];

    if(!tp || !pData)
        return TP_RET_PARAMETER_ERR;

    de_len=urldecode(buf, sizeof(buf)-1, pData->shopname, strlen(pData->shopname));
    if(de_len<0)
    {
        fprintf(stderr, "urldecode failed ret=%d\n", de_len);
    }
    else
    {
        for(i=0; i<de_len; i++)
            fprintf(stderr, "%02X", buf[i]);
            
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "read config info   name:%s        tpye:%d     int_type:%d     ip:%s           port:%d      instance:%d     handle_name:%s\n\n", 
        tp->name, tp->type, tp->intf_type, inet_ntoa(tp->ip), tp->port, tp->instance, tp->handle->name);

    fprintf(stderr, "pay data shopname\t\t\t:%s\n", pData->shopname);
    fprintf(stderr, "pay data token\t\t\t:%s\n", pData->token);
    fprintf(stderr, "pay data table\t\t\t:%s\n", pData->table);
    fprintf(stderr, "pay data date\t\t\t:%s\n", pData->date);
    fprintf(stderr, "pay data pepole\t\t\t:%d\n", pData->pepole);
    fprintf(stderr, "pay data total\t\t\t:%s\n", pData->total);
    for(i=0; i<pData->list_num; i++)
    {
        fprintf(stderr, "pay data list\t\t\t\t:name:%s\t\tcount:%d\t\tprice:%s\t\tsum:%s\t\tkip:%d\n", 
            pData->list[i].name, pData->list[i].count, pData->list[i].price, pData->list[i].sum, pData->list[i].kip);
    }
}
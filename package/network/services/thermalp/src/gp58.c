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

#define GP58_CASHIERP_DEV "/dev/usb/lp0"

static FILE *gp58_fp=NULL;

tpRet gp58_ca_open(void *ptr)
{
    gp58_fp=fopen(GP58_CASHIERP_DEV, "w");
    if(gp58_fp==NULL)
        return TP_RET_ERROR;
    else
        return TP_RET_SUCCESS;
}
tpRet gp58_ca_close(void *ptr)
{
    fclose(gp58_fp);
    gp58_fp=NULL;
    return TP_RET_SUCCESS;
}
tpRet gp58_ca_write(void *ptr, payData *pData)
{
    thermalpDev *tp_dev;
    int i;

    if(!ptr || !pData)
        return TP_RET_PARAMETER_ERR;

    tp_dev=(thermalpDev *)ptr;

    fprintf(stderr, "read config info   name:%s        tpye:%d     int_type:%d     ip:%s           port:%d      instance:%d     handle_name:%s\n\n", 
        tp_dev->name, tp_dev->type, tp_dev->intf_type, inet_ntoa(tp_dev->ip), tp_dev->port, tp_dev->instance, tp_dev->handle->name);

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
#if 0
    tpRet ret=TP_RET_SUCCESS;
    struct json_tokener *tok = NULL;
    json_object *obj;
    json_object *tmp, *item;
    const char *ptr;
    int val;
    int arr_len, i;
    
    if((str==NULL)||(str[0]==0))
        return TP_RET_PARAMETER_ERR;

    /*******common*******parse json string to json object start*/
    obj = json_tokener_parse(str);
    if (obj==NULL)
    {
        thermalp_error("string to json Obj error:%s\n", str);
        return TP_RET_JSON_PARSE_ERR;
    }
    /*******common*******parse json string to json object end*/

    if(get_string_from_jsonObj(obj, "shopname", &ptr)==TP_RET_SUCCESS)
        fprintf(stderr, "shopname:%s\n", ptr);

    if(get_string_from_jsonObj(obj, "token", &ptr)==TP_RET_SUCCESS)
        fprintf(stderr, "token:%s\n", ptr);

    if(get_string_from_jsonObj(obj, "table", &ptr)==TP_RET_SUCCESS)
        fprintf(stderr, "table:%s\n", ptr);

    if(get_string_from_jsonObj(obj, "date", &ptr)==TP_RET_SUCCESS)
        fprintf(stderr, "date:%s\n", ptr);

    if(get_int_from_jsonObj(obj, "pepole", &val)==TP_RET_SUCCESS)
        fprintf(stderr, "pepole:%d\n", val);

    if(get_int_from_jsonObj(obj, "total", &val)==TP_RET_SUCCESS)
        fprintf(stderr, "total:%d\n", val);

    /*******common*******parse json list from json object start*/
    if(!json_object_object_get_ex(obj, "list", &tmp))
    {
        thermalp_error("get list object failed\n");
        ret=TP_RET_JSON_GET_OBJECT_ERR;
        goto quit;
    }
    if (json_object_get_type(tmp) != json_type_array)
    {
        thermalp_error("get list type error\n");
        ret=TP_RET_JSON_GET_VALUE_TYPE_ERR;
        goto quit;
    }
    arr_len = json_object_array_length(tmp);
    if(arr_len==0)
    {
        thermalp_error("get list length error\n");
        ret=TP_RET_JSON_GET_VALUE_ERR;
        goto quit;
    }
    for(i=0; i<arr_len; i++)
    {
        item=json_object_array_get_idx(tmp, i);
        if(!item)
        {
            thermalp_error("get list item error\n");
            ret=TP_RET_JSON_GET_LIST_ERR;
            goto quit;
        }
        if(get_string_from_jsonObj(item, "name", &ptr)==TP_RET_SUCCESS)
            fprintf(stderr, "name:%s\n", ptr);

        if(get_int_from_jsonObj(obj, "price", &val)==TP_RET_SUCCESS)
            fprintf(stderr, "price:%d\n", val);

        if(get_int_from_jsonObj(obj, "count", &val)==TP_RET_SUCCESS)
            fprintf(stderr, "count:%d\n", val);

        if(get_int_from_jsonObj(obj, "sum", &val)==TP_RET_SUCCESS)
            fprintf(stderr, "sum:%d\n", val);

        if(get_int_from_jsonObj(obj, "kip", &val)==TP_RET_SUCCESS)
            fprintf(stderr, "kip:%d\n", val);
    }
    /*******common*******parse json list from json object end*/


quit:    
    /*******common*******free json object start*/
    json_object_put(obj);
    /*******common*******free json object end*/
    return ret;
#endif
}
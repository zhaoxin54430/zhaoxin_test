#ifndef __THERMALP_H
#define __THERMALP_H

#include <syslog.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <json-c/json.h>

#define THERMALP_OUTPUT_TO_SYSLOG

#ifdef THERMALP_OUTPUT_TO_SYSLOG
#define thermalp_error(args...) syslog(LOG_ERR, args)
#define thermalp_info(args...) syslog(LOG_INFO, args)
#else
#define thermalp_error(args...)
#define thermalp_info(args...)
#endif
#define TP_MODEL_NAME_MAX_LEN 32

typedef enum {
    TP_RET_PARAMETER_ERR=-101,
    TP_RET_JSON_PARSE_ERR=-102,
    TP_RET_JSON_TYPE_ERR=-103,
    TP_RET_JSON_GET_VALUE_ERR=-104,
    TP_RET_JSON_GET_VALUE_TYPE_ERR=-105,
    TP_RET_JSON_GET_OBJECT_ERR=-106,
    TP_RET_JSON_GET_LIST_ERR=-107,
    TP_RET_ERROR=-1,
    TP_RET_SUCCESS=0,
}tpRet;

typedef struct pay_data_list{
    const char *name;
    const char *price;
    int count;
    const char *sum;
    int kip;
}payDataList;

typedef struct pay_data{
    const char *shopname;
    const char *token;
    const char *table;
    const char *date;
    int pepole;
    const char *total;
    payDataList *list;
    int list_num;
}payData;

typedef struct thermalp_handle thermalpHandle;
typedef struct thermalp_dev thermalpDev;

struct thermalp_handle{
    char *name;
    /*for kitchen*/
    tpRet (*open)(thermalpDev *tp);
    tpRet (*write)(thermalpDev *tp, payData *pData);
    tpRet (*close)(thermalpDev *tp);
};

typedef enum {
	TP_USB,
	TP_ETH
}tp_intf_type;
typedef enum {
	TP_KITCHEN,
	TP_CASHIER
}tp_type;
struct thermalp_dev{
    char name[TP_MODEL_NAME_MAX_LEN];
    struct in_addr ip;
    uint16_t port;
    tp_type type;
    tp_intf_type intf_type;
    int instance;
    thermalpHandle *handle;
    FILE *fp;
};

typedef struct thermalp_conf{
    int num;
    thermalpDev *dev;
}thermalpConf;

int urldecode(char *buf, int blen, const char *src, int slen);
#endif
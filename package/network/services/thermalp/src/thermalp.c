/*
 *
 * Copyright 2012, Kochen <stephan@kochen.nl>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
    
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h>  
#include <time.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <others.h>
//#include <pthread.h> 
#include <uci.h>
#include <libubox/md5.h>
#include <libubox/blobmsg.h>
#include "thermalp.h"
#include "gp58.h"


/*

/etc/config/thermalp

config device dev1
    option type 'ki'  # ki(kitchen) or ca(cashier)
    option name 'gp58'  #device model name
    option intf_type 'usb' #usb or eth
    option ip '1.1.1.1'  #only for eth
    option port '789'  #only for eth
    option disabled '0'  #1 disable
    option instance '1'  #start from 1, ki and ca use different instance
config device dev2
    option type 'ki'  # ki(kitchen) or ca(cashier)
    option name 'gp58'  #device model name
    option intf_type 'usb' #usb or eth
    option ip '1.1.1.1'  #only for eth
    option port '789'  #only for eth
    option disabled '0'  #1 disable
    option instance '1'  #start from 1, ki and ca use different instance
......
*/
/*the actually is device mac address, so use br-lan*/
#define WAN_INTERFACE_NAME "eth0"

#define THERMALP_PID_FILE       "/tmp/thermalp_pid"
#define QUERY_TRY_TIMES 3
#define CURL_PERFORM_TIMEOUT 30 //seconds
#define CURL_DNS_CACHE_TIMEOUT 14400 //seconds
/*in the relase vesion, this must define to null!!!!!!!*/
#define main_function_debug  thermalp_info

#define TP_CONFIG_NAME "thermalp"
enum {
	TP_ATTR_TYPE,
	TP_ATTR_NAME,
	TP_ATTR_INTF_TYPE,
	TP_ATTR_IP,
	TP_ATTR_PORT,
	TP_ATTR_DISABLED,
	TP_ATTR_INSTANCE,
	TP_ATTR_MAX
};

static bool wan_hwaddr_valid=false;
static unsigned char wan_hwaddr[6];
static char query_mac_str[32];
static CURL *curl_handle=NULL;
static char post_response_buf[CURL_MAX_WRITE_SIZE];
static int post_response_buf_len=0;
static bool post_response_buf_ok=false;

static thermalpConf tp_conf={.num=0, .dev=NULL};

static const struct blobmsg_policy tp_attrs[TP_ATTR_MAX] = {
	[TP_ATTR_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
	[TP_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
	[TP_ATTR_INTF_TYPE] = { .name = "intf_type", .type = BLOBMSG_TYPE_STRING },
	[TP_ATTR_IP] = { .name = "ip", .type = BLOBMSG_TYPE_STRING },
	[TP_ATTR_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
	[TP_ATTR_DISABLED] = { .name = "disabled", .type = BLOBMSG_TYPE_BOOL },
	[TP_ATTR_INSTANCE] = { .name = "instance", .type = BLOBMSG_TYPE_INT32 },
};

static const thermalpHandle handlers_eth[]={
    { .name = "gp58", .open = NULL, .write = NULL, .close = NULL},
    { .name = NULL, .open = NULL, .write = NULL, .close = NULL},
};
static const thermalpHandle handlers_usb[]={
    { .name = "gp58", .open = NULL, .write = gp58_usb_write, .close = NULL},
    { .name = NULL, .open = NULL, .write = NULL, .close = NULL},
}; 

static int config_init(const char *config, thermalpConf *tp_conf)
{
    struct uci_context *ctx = NULL; //uci_ctx;
    struct uci_package *p = NULL;
    struct uci_element *e;
    struct uci_section *s;
    int num=0, index=0;
    int size=0, k;
    const char *disabled=NULL, *ptr=NULL;
    char name[TP_MODEL_NAME_MAX_LEN];
    struct in_addr ip;
    uint16_t port;
    tp_type type;
    tp_intf_type intf_type;
    int instance;
    bool exist=false;

    if(!config || !tp_conf)
        return -1;

    ctx = uci_alloc_context();
    ctx->flags &= ~UCI_FLAG_STRICT;

    if (uci_load(ctx, config, &p))
        goto quit3;

    uci_foreach_element(&p->sections, e) {
        s = uci_to_section(e);
        disabled = uci_lookup_option_string(ctx, s, "disabled");
        if (disabled && !strcmp(disabled, "1"))
            continue;
        num++;
    }
    if(num==0)
        goto quit2;

    size=num*sizeof(thermalpDev);
    tp_conf->dev=malloc(size);
    if(tp_conf->dev==NULL)
        goto quit2;
        
    memset(tp_conf->dev, 0, size);
    uci_foreach_element(&p->sections, e) {
        s = uci_to_section(e);
        disabled = uci_lookup_option_string(ctx, s, "disabled");
        if (disabled && !strcmp(disabled, "1"))
        {
            thermalp_error("config_init section disable, skip");
            continue;
        }
            
        ptr = uci_lookup_option_string(ctx, s, "type");
        if (ptr)
        {
            if(!strcmp(ptr, "ki"))
                type=TP_KITCHEN;
            else if(!strcmp(ptr, "ca"))
                type=TP_CASHIER;
            else
            {
                thermalp_error("config_init type illegal, skip");
                continue;
            }
        }
        else
        {
            thermalp_error("config_init type is null, skip");
            continue;
        }

        instance=1;
        ptr = uci_lookup_option_string(ctx, s, "instance");
        if (ptr && (atoi(ptr)>0))
            instance=atoi(ptr);

        exist=false;
        for(k=0;k<num;k++)
        {
            if((tp_conf->dev[k].instance==instance)&&(tp_conf->dev[k].type==type))
            {
                exist=true;
                break;
            }
        }
        if(exist)
        {
            thermalp_error("config_init instance exist, skip");
            continue;
        }
        
        ptr = uci_lookup_option_string(ctx, s, "name");
        if (ptr && (ptr[0]!=0))
        {
            strncpy(name, ptr, TP_MODEL_NAME_MAX_LEN-1);
            name[TP_MODEL_NAME_MAX_LEN-1]=0;
        }
        else
        {
            thermalp_error("config_init mode name is null, skip");
            continue;
        }

        ptr = uci_lookup_option_string(ctx, s, "intf_type");
        if (ptr)
        {
            if(!strcmp(ptr, "eth"))
                intf_type=TP_ETH;
            else if(!strcmp(ptr, "usb"))
                intf_type=TP_USB;
            else
            {
                thermalp_error("config_init interface type illegal, skip");
                continue;
            }
        }
        else
        {
            thermalp_error("config_init interface type is null, skip");
            continue;
        }

        ptr = uci_lookup_option_string(ctx, s, "ip");
        if (ptr)
        {
            if(inet_aton(ptr, &ip)==0)
            {
                thermalp_error("config_init parse ip error, skip");
                continue;
            }
        }
        else
        {
            thermalp_error("config_init ip is null, skip");
            continue;
        }

        port=9100;
        ptr = uci_lookup_option_string(ctx, s, "port");
        if (ptr)
            port=atoi(ptr);
        else
            thermalp_error("config_init port is null, use 9100");

        if(intf_type==TP_USB)
        {
            for(k=0;handlers_usb[k].name;k++)
            {
                if(strcmp(handlers_usb[k].name, name)==0)
                {
                    tp_conf->dev[index].handle=&(handlers_usb[k]);
                    break;
                }
            }
        }
        else if(intf_type==TP_ETH)
        {
            for(k=0;handlers_eth[k].name;k++)
            {
                if(strcmp(handlers_eth[k].name, name)==0)
                {
                    tp_conf->dev[index].handle=&(handlers_eth[k]);
                    break;
                }
            }
        }

        tp_conf->dev[index].intf_type=intf_type;
        tp_conf->dev[index].type=type;
        tp_conf->dev[index].port=port;
        tp_conf->dev[index].instance=instance;
        strcpy(tp_conf->dev[index].name, name);
        memcpy(&(tp_conf->dev[index].ip), &ip, sizeof(struct in_addr));
        index++;
    }
    if(index==0)
        goto quit1;

    tp_conf->num=index;
    if (p)
        uci_unload(ctx, p);
    uci_free_context(ctx); 
    return 0;

quit1:
    free(tp_conf->dev);
    tp_conf->dev=NULL;

quit2:
    if (p)
        uci_unload(ctx, p);
    
quit3:
    uci_free_context(ctx);
    return -1;
}
tpRet get_string_from_jsonObj(json_object *obj, const char *name, const char **val)
{
    json_object *tmp;
    const char *ptr;

    if((obj==NULL)||(name==NULL)||(val==NULL))
        return TP_RET_PARAMETER_ERR;

    if(!json_object_object_get_ex(obj, name, &tmp))
    {
        thermalp_error("get string %s object failed\n", name);
        return TP_RET_JSON_GET_OBJECT_ERR;
    }
    if (json_object_get_type(tmp) != json_type_string)
    {
        thermalp_error("get string %s type error\n", name);
        return TP_RET_JSON_GET_VALUE_TYPE_ERR;
    }
    ptr = json_object_get_string(tmp);
    if(!ptr)
    {
        thermalp_error("get string %s value failed\n", name);
        return TP_RET_JSON_GET_VALUE_ERR;
    }
    else
    {
        *val=ptr;
        return TP_RET_SUCCESS;
    }
}
tpRet get_int_from_jsonObj(json_object *obj, const char *name, int *val)
{
    json_object *tmp;

    if((obj==NULL)||(name==NULL)||(val==NULL))
        return TP_RET_PARAMETER_ERR;

    if(!json_object_object_get_ex(obj, name, &tmp))
    {
        thermalp_error("get int %s object failed\n", name);
        return TP_RET_JSON_GET_OBJECT_ERR;
    }
    if (json_object_get_type(tmp) != json_type_int)
    {
        thermalp_error("get int %s type error\n", name);
        return TP_RET_JSON_GET_VALUE_TYPE_ERR;
    }
    *val = json_object_get_int(tmp);
    return TP_RET_SUCCESS;
}

tpRet parse_paydata(char *str, json_object **object, payData **pData)
{
    tpRet ret=TP_RET_SUCCESS;
    json_object *obj;
    json_object *tmp, *item;
    const char *ptr;
    payData *pay;
    int val;
    int arr_len, i;
    
    if((!str)||(str[0]==0)||(!pData)||(!object))
        return TP_RET_PARAMETER_ERR;

    *pData=NULL;
    *object=NULL;
    /*parse json string to json object*/
    obj = json_tokener_parse(str);
    if (obj==NULL)
    {
        thermalp_error("string to json Obj error:%s\n", str);
        return TP_RET_JSON_PARSE_ERR;
    }
    /*get list object, and length*/
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

    pay=calloc(1,sizeof(payData));
    if(!pay)
    {
        thermalp_error("malloc payData error\n");
        ret=TP_RET_JSON_PARSE_ERR;
        goto quit;
    }
    pay->list=calloc(arr_len, sizeof(payDataList));
    if(!pay->list)
    {
        thermalp_error("malloc payDataList error\n");
        ret=TP_RET_JSON_PARSE_ERR;
        goto quit1;
    }

    ret=get_string_from_jsonObj(obj, "shopname", &ptr);
    if(ret==TP_RET_SUCCESS)
        pay->shopname=ptr;
    else
        goto quit2;

    ret=get_string_from_jsonObj(obj, "token", &ptr);
    if(ret==TP_RET_SUCCESS)
        pay->token=ptr;
    else
        goto quit2;

    ret=get_string_from_jsonObj(obj, "table", &ptr);
    if(ret==TP_RET_SUCCESS)
        pay->table=ptr;
    else
        goto quit2;

    ret=get_string_from_jsonObj(obj, "date", &ptr);
    if(ret==TP_RET_SUCCESS)
        pay->date=ptr;
    else
        goto quit2;

    ret=get_int_from_jsonObj(obj, "pepole", &val);
    if(ret==TP_RET_SUCCESS)
        pay->pepole=val;
    else
        goto quit2;
        
    ret=get_string_from_jsonObj(obj, "total", &ptr);
    if(ret==TP_RET_SUCCESS)
        pay->total=ptr;
    else
        goto quit2;

    for(i=0; i<arr_len; i++)
    {
        item=json_object_array_get_idx(tmp, i);
        if(!item)
        {
            thermalp_error("get list item error\n");
            ret=TP_RET_JSON_GET_LIST_ERR;
            goto quit2;
        }
        ret=get_string_from_jsonObj(item, "name", &ptr);
        if(ret==TP_RET_SUCCESS)
            pay->list[i].name=ptr;
        else
            goto quit2;

        ret=get_string_from_jsonObj(item, "price", &ptr);
        if(ret==TP_RET_SUCCESS)
            pay->list[i].price=ptr;
        else
            goto quit2;

        ret=get_int_from_jsonObj(item, "count", &val);
        if(ret==TP_RET_SUCCESS)
            pay->list[i].count=val;
        else
            goto quit2;

        ret=get_string_from_jsonObj(item, "sum", &ptr);
        if(ret==TP_RET_SUCCESS)
            pay->list[i].sum=ptr;
        else
            goto quit2;
            
        ret=get_int_from_jsonObj(item, "kip", &val);
        if(ret==TP_RET_SUCCESS)
            pay->list[i].kip=val;
        else
            goto quit2;

        pay->list_num++;

    }
    *pData=pay;
    *object=obj;
    return TP_RET_SUCCESS;

quit2:    
    if(pay->list)
        free(pay->list);

quit1:    
    if(pay)
        free(pay);
        
quit:    
    json_object_put(obj);
    return ret;

}
void parse_paydata_free(json_object *object, payData *pData)
{
    if(pData)
    {
        if(pData->list)
            free(pData->list);
        free(pData);
    }
    if(object)
        json_object_put(object);
}
bool get_wan_hwaddr(unsigned char *wan_hwaddr)
{
    int fd=-1;
    bool success=false;
    struct ifreq ifr;
    
    if(!wan_hwaddr)
        return success;
        
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) 
    {
        strcpy(ifr.ifr_name, WAN_INTERFACE_NAME);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) 
        {
            memcpy(wan_hwaddr, ifr.ifr_hwaddr.sa_data, 6);
            thermalp_info("wan hardware address %02x:%02x:%02x:%02x:%02x:%02x",
            	wan_hwaddr[0], wan_hwaddr[1], wan_hwaddr[2], 
            	wan_hwaddr[3], wan_hwaddr[4], wan_hwaddr[5]);
            success=true;
        } 
        else 
        {
            thermalp_info("SIOCGIFHWADDR failed! %s", strerror(errno));
        }
        close(fd);
    } 
    else
    {
        thermalp_info("socket failed! %s", strerror(errno));
    }
    return success;
}

void curl_init(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    if(!curl_handle)
    {
        thermalp_error("curl_easy_init failed");
    }
    return;
}
size_t post_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t all_size=nmemb*size;
    
    //thermalp_error("get response data:%s", ptr);
    if(all_size>0)
    {
        if((all_size+post_response_buf_len)<(CURL_MAX_WRITE_SIZE))
        {
            memcpy(&post_response_buf[post_response_buf_len], ptr, all_size);
            post_response_buf_len+=all_size;
            post_response_buf[post_response_buf_len]=0;
            post_response_buf_ok=true;
            main_function_debug("post response data:%s", post_response_buf);
        }
        else
        {
            post_response_buf_ok=false;
            thermalp_error("get response is more than %d bytes", CURL_MAX_WRITE_SIZE);
        }
    }
    main_function_debug("post response size:%d", all_size);
    return(all_size);
}
CURLcode curl_post_init(char *url)
{
    CURLcode res=CURLE_HTTP_RETURNED_ERROR;

    if( !url  )
    {
        thermalp_error("curl_post url null");
        return res;
    }
    
    if(curl_handle)
    {
        res=curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_URL error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_POST error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, post_write_callback);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_WRITEFUNCTION error");
            return res;
        }        
        res=curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, CURL_PERFORM_TIMEOUT);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_TIMEOUT error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_DNS_CACHE_TIMEOUT, CURL_DNS_CACHE_TIMEOUT);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_DNS_CACHE_TIMEOUT error");
            return res;
        }
        /*after perform, close the socket*/
        res=curl_easy_setopt(curl_handle, CURLOPT_FORBID_REUSE, 1L);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_FORBID_REUSE error");
            return res;
        }
    }
    return res;
}

/*
 * The data pointed to is NOT copied by the library: as a consequence, 
 * it must be preserved by the calling application until the associated transfer finishes.
 * libcurl will not convert or encode it for you in any way. For example, 
 * the web server may assume that this data is url-encoded.
 * You can use curl_easy_escape to url-encode your data, if necessary. 
 * It returns a pointer to an encoded string that can be passed as postdata. 
*/
CURLcode curl_post_data(char *data, int data_len)
{
    CURLcode res=CURLE_HTTP_RETURNED_ERROR;

    if( !data || (data_len==0) )
    {
        thermalp_error("post_data arg error");
        return res;
    }
    
    if(curl_handle)
    {      
        res=curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_POSTFIELDS error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, data_len);
        if(res != CURLE_OK)
        {
            thermalp_error("CURLOPT_POSTFIELDSIZE error");
            return res;
        }
    }
    return res;
}
/*
 * return 1, do noting 
 * return 0, OK
 * return -1, failed
*/
int poll_pay_data(char *token)
{
    int i=0;
    char buf[128];
    long response_code;
    CURLcode res;
    struct timespec now_time = {0, 0};

    if(!token)
        return 1;
        
    if(wan_hwaddr_valid==false)
    {
        if(get_wan_hwaddr(wan_hwaddr))
        {
            wan_hwaddr_valid=true;
            sprintf(query_mac_str, "dev=%02x%02x%02x%02x%02x%02x", 
                wan_hwaddr[0], wan_hwaddr[1], wan_hwaddr[2],
                wan_hwaddr[3], wan_hwaddr[4], wan_hwaddr[5]);
        }
        else
        {/*try again*/
            if(get_wan_hwaddr(wan_hwaddr))
            {
                wan_hwaddr_valid=true;
                sprintf(query_mac_str, "dev=%02x%02x%02x%02x%02x%02x", 
                    wan_hwaddr[0], wan_hwaddr[1], wan_hwaddr[2],
                    wan_hwaddr[3], wan_hwaddr[4], wan_hwaddr[5]);
            }
            else
            {
                thermalp_error("try get wan mac agian fail");
                return 1; /*get wan mac failed, ??*/
            }
        }
        
    }
    sprintf(buf, "%stoken=%s", query_mac_str, token);
    main_function_debug("query param %s ", buf);
    for(i=0; i<QUERY_TRY_TIMES; i++)
    {
        if(curl_post_data(buf, strlen(buf))!=CURLE_OK)
        {
            thermalp_error("curl set post data failed");
            continue;
        }
        else
        {
            post_response_buf_ok=false;
            post_response_buf_len=0;
            res = curl_easy_perform(curl_handle);
            if(res != CURLE_OK)
            {
                thermalp_error("curl perform failed res=%d ", res);
                continue;
            }
        }
        if(curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code)==CURLE_OK)
        {
            //thermalp_error("curl perform response code %d", response_code);
            main_function_debug("auth check resp_code=%d buf_ok=%d resp_buf=%s", response_code, 
                        post_response_buf_ok ,post_response_buf);
            if((response_code==200)&&(post_response_buf_ok))
            {
                return 0;
            }
        }
    }
    return -1;
}
static void open_all(void)
{
    int i=0;
    for(i=0;i<tp_conf.num; i++)
    {
        if(tp_conf.dev[i].handle)
        {
            if((tp_conf.dev[i].handle->open==NULL)||(tp_conf.dev[i].handle->open(&tp_conf.dev[i])!=TP_RET_SUCCESS))
            {
                thermalp_error("call open function failed for dev:%s intf_type:%d", tp_conf.dev[i].name, tp_conf.dev[i].intf_type);
            }
        }
    }
}
static void close_all(void)
{
    int i=0;
    for(i=0;i<tp_conf.num; i++)
    {
        if(tp_conf.dev[i].handle)
        {
            if((tp_conf.dev[i].handle->close==NULL)||(tp_conf.dev[i].handle->close(&tp_conf.dev[i])!=TP_RET_SUCCESS))
            {
                thermalp_error("call close function failed for dev:%s intf_type:%d", tp_conf.dev[i].name, tp_conf.dev[i].intf_type);
            }
        }
    }
}

/* blen is the size of buf; slen is the length of src.  The input-string need
** not be, and the output string will not be, null-terminated.  Returns the
** length of the decoded string, -1 on buffer overflow, -2 on malformed string. */
int urldecode(char *buf, int blen, const char *src, int slen)
{
	int i;
	int len = 0;

#define hex(x) \
	(((x) <= '9') ? ((x) - '0') : \
		(((x) <= 'F') ? ((x) - 'A' + 10) : \
			((x) - 'a' + 10)))

	for (i = 0; (i < slen) && (len < blen); i++)
	{
		if (src[i] != '%') {
			buf[len++] = src[i];
			continue;
		}

		if (i + 2 >= slen || !isxdigit(src[i + 1]) || !isxdigit(src[i + 2]))
			return -2;

		buf[len++] = (char)(16 * hex(src[i+1]) + hex(src[i+2]));
		i += 2;
	}
	buf[len] = 0;

	return (i == slen) ? len : -1;
}
#if 0
static void sigHandler_user(int signo)
{
    main_function_debug("recv signal %d", signo);
}
#endif
int main(int argc, char **argv)
{  
    //FILE *pid_file=NULL;
    int i=0, k=0;
    time_t temp_time=0;
    CURLcode res;
    char temp_buf[256];
    thermalpDev *dev=NULL;
    json_object *jObj;
    payData *pData;

    signal(SIGPIPE, SIG_IGN);
    openlog("thermalp", LOG_NDELAY , LOG_USER);

    if(config_init("thermalp", &tp_conf)!=0)
    {
        thermalp_error("parse /etc/config/thermalp file failed");
        exit (-1);
    }
    if(get_wan_hwaddr(wan_hwaddr))
    {
        wan_hwaddr_valid=true;
        sprintf(query_mac_str, "dev=%02x%02x%02x%02x%02x%02x", 
            wan_hwaddr[0], wan_hwaddr[1], wan_hwaddr[2],
            wan_hwaddr[3], wan_hwaddr[4], wan_hwaddr[5]);
    }
    else
    {
        /*in the bootup, get the wan hwaddr will failed, 
        so if wan_hwaddr_valid=false, need do again in the below*/
        thermalp_error("get_wan_hwaddr failed");
    }   
    curl_init();
    if(curl_post_init(THERMALP_PATH)!=CURLE_OK)
    {
        if(curl_handle)
            curl_easy_cleanup(curl_handle);
            
        curl_global_cleanup();
        goto quit;
    }
#if 0    
    signal(SIGUSR1, sigHandler_user);
    /*write pid*/
    pid_file=fopen(THERMALP_PID_FILE,"w");
    if(pid_file==NULL)
    {
        thermalp_error("open"THERMALP_PID_FILE"failed");
    }
    else
    {
        fprintf(pid_file, "%d", getpid());
        fclose(pid_file);
    }
#endif
    open_all();
    //poll failed retry, parse faild can't retry
    if(poll_pay_data("15dbe2123ceb17")==0)
    {
        if(parse_paydata(post_response_buf, &jObj, &pData)==TP_RET_SUCCESS)
        {
            for(i=0;i<tp_conf.num; i++)
            {
                if(tp_conf.dev[i].handle)
                {
                    if((tp_conf.dev[i].handle->write==NULL)||(tp_conf.dev[i].handle->write(&tp_conf.dev[i], pData)!=TP_RET_SUCCESS))
                    {
                        thermalp_error("call write function failed for dev:%s intf_type:%d", tp_conf.dev[i].name, tp_conf.dev[i].intf_type);
                    }
                }
            }
            parse_paydata_free(jObj, pData);
        }
    }
    
    close_all();
/*
    while(true)
    {
        auth_check_ret=poll_pay_data();
        if(auth_check_ret !=1)
        {
        }
    }
    */
    
    if(curl_handle)
        curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
    closelog();
    exit(0);

quit:
    closelog();
    exit(1);   
} 


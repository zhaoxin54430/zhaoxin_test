/*
 *
 * Copyright 2012, Sté‘¼å²han Kochen <stephan@kochen.nl>
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
#include <libshmem.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include "clatdm.h"
#include "others.h"

#define CHECK_AUTH_TIMEOUT  180  //seconds
#define AUTH_SUCCESS_TIMEOUT  43200 //seconds 12 hours
#define WAN_INTERFACE_NAME "eth0.2"
#define CURL_PERFORM_TIMEOUT 40 //seconds
#define CURL_DNS_CACHE_TIMEOUT 14400 //seconds

all_client_info *shm_ptr=NULL;
static bool wan_hwaddr_valid=false;
static char wan_hwaddr[6];
static CURL *curl_handle=NULL;

bool get_wan_hwaddr(char *wan_hwaddr)
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
            clatdm_info("wan hardware address %02x:%02x:%02x:%02x:%02x:%02x",
            	0xFF&wan_hwaddr[0], 0xFF&wan_hwaddr[1], 0xFF&wan_hwaddr[2], 
            	0xFF&wan_hwaddr[3], 0xFF&wan_hwaddr[4], 0xFF&wan_hwaddr[5]);
            success=true;
        } 
        else 
        {
            clatdm_info("SIOCGIFHWADDR failed! %s", strerror(errno));
        }
    } 
    else
    {
        clatdm_info("socket failed! %s", strerror(errno));
    }
    close(fd);
    return success;
}

void curl_init(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    if(!curl_handle)
    {
        clatdm_error("curl_easy_init failed");
    }
    return;
}
size_t get_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t all_size=nmemb*size;
    char buf[64];
    
    //clatdm_error("get response data:%s", ptr);
    if(all_size<(sizeof(buf)-1))
    {
        memcpy(buf, ptr, all_size);
        buf[all_size]=0;
        clatdm_error("get response data:%s", buf);
    }
    clatdm_error("get response size:%d", all_size);
    return(all_size);
}
size_t post_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t all_size=nmemb*size;
    char buf[64];
    
    //clatdm_error("get response data:%s", ptr);
    if(all_size<(sizeof(buf)-1))
    {
        memcpy(buf, ptr, all_size);
        buf[all_size]=0;
        clatdm_error("post response data:%s", buf);
    }
    clatdm_error("post response size:%d", all_size);
    return(all_size);
}
CURLcode curl_get_init(char *url)
{
    CURLcode res=CURLE_HTTP_RETURNED_ERROR;
    
    if( !url )
    {
        clatdm_error("curl_get url null");
        return res;
    }
    
    if(curl_handle)
    {
        res=curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_URL error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, get_write_callback);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_WRITEFUNCTION error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, CURL_PERFORM_TIMEOUT);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_TIMEOUT error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_DNS_CACHE_TIMEOUT, CURL_DNS_CACHE_TIMEOUT);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_DNS_CACHE_TIMEOUT error");
            return res;
        }
        /*after perform, close the socket*/
        res=curl_easy_setopt(curl_handle, CURLOPT_FORBID_REUSE, 1L);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_FORBID_REUSE error");
            return res;
        }
    }
    return res;
}
CURLcode curl_post_init(char *url)
{
    CURLcode res=CURLE_HTTP_RETURNED_ERROR;

    if( !url  )
    {
        clatdm_error("curl_post url null");
        return res;
    }
    
    if(curl_handle)
    {
        res=curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_URL error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_POST error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, post_write_callback);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_WRITEFUNCTION error");
            return res;
        }        
        res=curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, CURL_PERFORM_TIMEOUT);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_TIMEOUT error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_DNS_CACHE_TIMEOUT, CURL_DNS_CACHE_TIMEOUT);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_DNS_CACHE_TIMEOUT error");
            return res;
        }
        /*after perform, close the socket*/
        res=curl_easy_setopt(curl_handle, CURLOPT_FORBID_REUSE, 1L);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_FORBID_REUSE error");
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
        clatdm_error("post_data arg error");
        return res;
    }
    
    if(curl_handle)
    {      
        res=curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_POSTFIELDS error");
            return res;
        }
        res=curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, data_len);
        if(res != CURLE_OK)
        {
            clatdm_error("CURLOPT_POSTFIELDSIZE error");
            return res;
        }
    }
    return res;
}

int main(int argc, char **argv)
{  
    void *ptr=NULL;
    client_info client;
    char attachExisting=false;
    FILE *flag_file=NULL;
    int i=0;
    time_t temp_time=0;
    CURLcode res;

    if(access(SHARE_MEM_FLAG, F_OK)==0)
        attachExisting=true;

    signal(SIGPIPE, SIG_IGN);
    openlog("clatdm", LOG_NDELAY , LOG_USER);

    shm_ptr=NULL;
    if(Lock_init(attachExisting)!=SHMRET_SUCCESS)
    {
        clatdm_error("Lock_init failed, errno=%d", errno);
        closelog();
        exit(1);
    }
    /*only management process init sem*/
    if(attachExisting==false)
    {
        if(init_sem()!=SHMRET_SUCCESS)
        {
            clatdm_error("init_sem failed, errno=%d", errno);
            goto quit_lock;
        }
    }
    if(shm_mem_init(attachExisting)!=SHMRET_SUCCESS)
    {
        clatdm_error("shm_mem_init failed, errno=%d", errno);
        goto quit_lock;
    }
    else
    {
        if(attachExisting==false)
        {
            flag_file=fopen(SHARE_MEM_FLAG,"w+");
            if(flag_file==NULL)
            {
                Lock_cleanup();
                closelog();
                exit(1);
            }
            else
            {
                fclose(flag_file);
            }
        }
    }
    ptr=shm_mem_attach();
    if(ptr==(void *)(-1))
    {
        clatdm_error("shm_mem_attach failed, errno=%d", errno);
        goto quit_lock;
    }
    shm_ptr=(all_client_info *)ptr;
    
    if(attachExisting==false)
    {
        sem_lock();
        /*only management process init the number*/
        shm_ptr->client_num=0;
        sem_unlock();
    }

    if(get_wan_hwaddr(wan_hwaddr))
    {
        wan_hwaddr_valid=true;
    }
    else
    {
        clatdm_error("get_wan_hwaddr failed");
        goto quit_mem;
    }
//clatdm_error("sizeof client_info %d", sizeof(client_info));    
    curl_init();
    if(curl_post_init(CLATDM_PATH)!=CURLE_OK)
    {
        if(curl_handle)
            curl_easy_cleanup(curl_handle);
            
        curl_global_cleanup();
        goto quit_mem;
    }
    if(curl_post_data("auth=BCD1773432C8", strlen("auth=BCD1773432C8"))!=CURLE_OK)
    {
        clatdm_error("curl set post data failed %s", curl_easy_strerror(res));
    }
    else
    {
        res = curl_easy_perform(curl_handle);
        if(res != CURLE_OK)
            clatdm_error("curl perform failed %s", curl_easy_strerror(res));
    }
#if 0  
    sleep(180);
    if(curl_post_data("auth=0210183344AF", strlen("auth=0210183344AF"))!=CURLE_OK)
    {
        clatdm_error("curl set post data failed %s", curl_easy_strerror(res));
    }
    else
    {
        res = curl_easy_perform(curl_handle);
        if(res != CURLE_OK)
            clatdm_error("curl perform failed %s", curl_easy_strerror(res));
    }
#endif

    long response_code;
    if(curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code)==CURLE_OK)
    {
        clatdm_error("curl perform response code %d", response_code);
    }
    while(true)
    {
#if 0    
        sem_lock();
        for(i=0; i<shm_ptr->client_num; i++)
        {
            memcpy(&client, &(shm_ptr->client[i]), sizeof(client_info));
        }
        sem_unlock();
#else
    sleep(180);
#endif
    }
    shm_mem_detach(ptr);
    shm_ptr=NULL;
    
    if(curl_handle)
        curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
    //shm_mem_cleanup();
    //Lock_cleanup();
    closelog();
    exit(0);

quit_lock:
    //Lock_cleanup();
    closelog();
    exit(1);
    
quit_mem:
    shm_mem_detach(ptr);
    //shm_mem_cleanup();
    //Lock_cleanup();
    closelog();
    exit(1);    
} 
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

#define AUTH_SUCCESS_TIMEOUT  43200 //seconds 12 hours
#define WAN_INTERFACE_NAME "eth0.2"
#define CURL_PERFORM_TIMEOUT 40 //seconds
#define CURL_DNS_CACHE_TIMEOUT 14400 //seconds

#define CLATDM_LOOP_INTERVAL CHECK_AUTH_TIMEOUT //seconds
#define DETECT_LEAVE_INTERVAL (4*CLATDM_LOOP_INTERVAL)
#define NO_ARP_TIMES 10
#define CLATDM_AUTH_CHECK_TIMES 3
#define BRIDGE_INTERFACE_NAME "br-lan"
#define ARP_MAX_CLIENTS_NUMBER (MAX_CLIENTS_NUMBER+32)

all_client_info *shm_ptr=NULL;
static bool wan_hwaddr_valid=false;
static unsigned char wan_hwaddr[6];
static bool bridge_ipaddr_valid=false;
static unsigned char bridge_ipaddr[32];
static CURL *curl_handle=NULL;
static char post_response_buf[64];
static bool post_response_buf_ok=false;

#define ARP_CACHE       "/proc/net/arp"
#define ARP_LINE_FORMAT "%s %*s %*s %s %*s %*s"
#define ARP_BUFFER_LEN 128

typedef struct arpInfo{
    unsigned char mac_addr[6];
    uint32_t ip4_addr;
}arp_info;

typedef struct allArpInfo{
    char client_num;
    arp_info client[ARP_MAX_CLIENTS_NUMBER];
}all_arp_info;

static all_arp_info client_arp_info;

/* Convert from 00:AA:00:BB:00:CC to 00AA00BB00CC
*/      
void string_to_mac_address(char* src,char* dest)
{
    const char *s = src;
    size_t len = strlen(src);

	if (len) {
		/* Copy string up to the maximum size of the dest buffer */
		while (len!= 0) {
			if(*s==':')
			{
				s++;
				len--;
				continue;
			}
			if(*s== '\0')
				break;
			*dest=*s;
			s++;
			dest++;
			len--;
		}
		*dest = '\0';
	}

}

static int _is_hex(char c)
{
    return (((c >= '0') && (c <= '9')) ||
            ((c >= 'A') && (c <= 'F')) ||
            ((c >= 'a') && (c <= 'f')));
}

void string_to_hex(char *string, char *key, int len)
{
	char tmpBuf[4];
	int idx, ii=0;
	for (idx=0; idx<len; idx+=2) {
		tmpBuf[0] = string[idx];
		tmpBuf[1] = string[idx+1];
		tmpBuf[2] = 0;
		if ( !_is_hex(tmpBuf[0]) || !_is_hex(tmpBuf[1]))
			return 0;

		key[ii++] = (char) strtol(tmpBuf, (char**)NULL, 16);
	}
	return 1;
}

int get_arp_info(void)
{
    char tmpbuf[ARP_BUFFER_LEN];
    char ipAddr[32], hwAddr[32];
    struct in_addr addr;
    int count = 0;

    client_arp_info.client_num=0;
    
    FILE *arpCache = fopen(ARP_CACHE, "r");
    if (!arpCache)
    {
        clatdm_error("open file \"" ARP_CACHE "\" failed");
        return -1;
    }
    if (!fgets(tmpbuf, sizeof(tmpbuf), arpCache))
    {
        return -1;
    }
    memset(tmpbuf, 0, sizeof(tmpbuf));
    while (2 == fscanf(arpCache, ARP_LINE_FORMAT, ipAddr, hwAddr))
    {
        inet_aton(ipAddr, &addr);
        client_arp_info.client[client_arp_info.client_num].ip4_addr=ntohl(addr.s_addr);
        string_to_mac_address(hwAddr, tmpbuf);
        string_to_hex(tmpbuf, client_arp_info.client[client_arp_info.client_num].mac_addr, 12);
#if 0       
        clatdm_info("arp ip=%x  mac=%02x:%02x:%02x:%02x:%02x:%02x", 
            client_arp_info.client[client_arp_info.client_num].ip4_addr, 
            client_arp_info.client[client_arp_info.client_num].mac_addr[0],
            client_arp_info.client[client_arp_info.client_num].mac_addr[1],
            client_arp_info.client[client_arp_info.client_num].mac_addr[2],
            client_arp_info.client[client_arp_info.client_num].mac_addr[3],
            client_arp_info.client[client_arp_info.client_num].mac_addr[4],
            client_arp_info.client[client_arp_info.client_num].mac_addr[5]);
#endif
        if(client_arp_info.client_num<ARP_MAX_CLIENTS_NUMBER)
            client_arp_info.client_num++;
        else
            clatdm_error("client_arp_info is full");
    }
    fclose(arpCache);
    return 0;
}

#ifndef IFNAMSIZ
#define IFNAMSIZ  16
#endif
bool get_ifaddr(const char *ifname, struct in_addr *inaddr)
{
	int sockfd;
	struct ifreq ifreq;

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		//perror("socket");
		return false;
	}

	strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFADDR, &ifreq) < 0) {
		close(sockfd);
		return false;
	}
	else {
		memcpy(inaddr, &(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr),
			sizeof(struct in_addr));
	}

	close(sockfd);
	return true;
}

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
            	wan_hwaddr[0], wan_hwaddr[1], wan_hwaddr[2], 
            	wan_hwaddr[3], wan_hwaddr[4], wan_hwaddr[5]);
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
    
    //clatdm_error("get response data:%s", ptr);
    if(all_size<(sizeof(post_response_buf)-1))
    {
        memcpy(post_response_buf, ptr, all_size);
        post_response_buf[all_size]=0;
        post_response_buf_ok=true;
        //clatdm_error("post response data:%s", post_response_buf);
    }
    //clatdm_error("post response size:%d", all_size);
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
/*
 * return 1, do noting 
 * return 0, OK
 * return -1, failed
*/
int clatdm_auth_check(client_info *client)
{
    int i=0;
    char buf[128];
    long response_code;
    CURLcode res;
    
    /*arg is null, do noting*/
    if((client==NULL)||(client->ip4_addr==0))
        return 1;

    if(wan_hwaddr_valid==false)
    {
        if(get_wan_hwaddr(wan_hwaddr))
            wan_hwaddr_valid=true;
        else
        {/*try again*/
            if(get_wan_hwaddr(wan_hwaddr))
                wan_hwaddr_valid=true;
            else
            {
                clatdm_error("try get wan mac agian fail");
                return 0; /*get wan mac failed, ??*/
            }
        }
        
    }
    sprintf(buf, "%02X%02X%02X%02X%02X%02X%08X%02X%02X%02X%02X%02X%02X", 
                                wan_hwaddr[0], wan_hwaddr[1], wan_hwaddr[2],
                                wan_hwaddr[3], wan_hwaddr[4], wan_hwaddr[5],
                                client->ip4_addr, 
                                client->mac_addr[0], client->mac_addr[1], client->mac_addr[2], 
                                client->mac_addr[3], client->mac_addr[4], client->mac_addr[5]);
    
    for(i=0; i<CLATDM_AUTH_CHECK_TIMES; i++)
    {
        if(curl_post_data(buf, strlen(buf))!=CURLE_OK)
        {
            clatdm_error("curl set post data failed %s", curl_easy_strerror(res));
            continue;
        }
        else
        {
            post_response_buf_ok=false;
            res = curl_easy_perform(curl_handle);
            if(res != CURLE_OK)
            {
                clatdm_error("curl perform failed %s", curl_easy_strerror(res));
                continue;
            }
        }
        if(curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code)==CURLE_OK)
        {
            //clatdm_error("curl perform response code %d", response_code);
            if((response_code==200)&&(post_response_buf_ok))
            {
                if(post_response_buf[0]=='1')
                    return 0;
                else
                    return -1;
            }
        }
    }
    return -1;
}
int main(int argc, char **argv)
{  
    void *ptr=NULL;
    client_info client;
    char attachExisting=false;
    FILE *flag_file=NULL;
    int i=0, k=0;
    time_t temp_time=0;
    CURLcode res;
    struct timeval delay = {0, 0};
    struct timespec now_time = {0, 0};
    time_t interval_sec=0, next_detect_time=0;
    char detect_leave_times=0;
    bool arp_found=false;
    int auth_check_ret;
    char temp_buf[256];
    struct in_addr gw_addr, ip_addr;

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
        /*in the bootup, get the wan hwaddr will failed, 
        so if wan_hwaddr_valid=false, need do again in the below*/
        clatdm_error("get_wan_hwaddr failed");
        //goto quit_mem;
    }
    if(get_ifaddr(BRIDGE_INTERFACE_NAME, &gw_addr))
    {
        bridge_ipaddr_valid=true;
        strcpy(bridge_ipaddr, inet_ntoa(gw_addr));
    }
    else
    {
        /*in the bootup, get bridge ipaddr maybe failed, 
        so if bridge_ipaddr=false, need do again in the below*/
        clatdm_error("get bridge ipaddr failed");
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

    clock_gettime(CLOCK_MONOTONIC, &now_time);
    next_detect_time=now_time.tv_sec+DETECT_LEAVE_INTERVAL;
    client.ip4_addr=0;
    while(true)
    {
        /*do the auth check for last loop*/
        if(client.ip4_addr!=0)
        {
            auth_check_ret=clatdm_auth_check(&client);
            if(auth_check_ret !=1)
            {
                sem_lock();
                for(i=0; i<shm_ptr->client_num; i++)
                {
                    if((client.ip4_addr==shm_ptr->client[i].ip4_addr)&&
                        (memcmp(shm_ptr->client[i].mac_addr, client.mac_addr, 6)==0))
                    {
                        if(auth_check_ret==0)
                        {
                            shm_ptr->client[i].status=AUTH_SUCCESSFUL; //auth success
                            shm_ptr->client[i].detec_leave=0;
                        }
                        else
                            shm_ptr->client[i].status=REDIRECT_RULE; //auth failed
                        break;
                    }
                }
                sem_unlock();
            }
            /*auth failed process firewall rules*/
            if(auth_check_ret==-1)
            {
                ip_addr.s_addr=htonl(client.ip4_addr);
                sprintf(temp_buf, DELETE_ALLOW_RULE_FORMAT, inet_ntoa(ip_addr));
                system(temp_buf);

                if(bridge_ipaddr_valid==false)
                {
                    if(get_ifaddr(BRIDGE_INTERFACE_NAME, &gw_addr))
                    {
                        bridge_ipaddr_valid=true;
                        strcpy(bridge_ipaddr, inet_ntoa(gw_addr));
                    }
                    else
                    {/*try again*/
                        if(get_ifaddr(BRIDGE_INTERFACE_NAME, &gw_addr))
                        {
                            bridge_ipaddr_valid=true;
                            strcpy(bridge_ipaddr, inet_ntoa(gw_addr));
                        }
                        else
                        {
                            clatdm_error("try get bridge ipaddr fail");
                        }
                    }
                }
                if(bridge_ipaddr_valid)
                {
                    sprintf(temp_buf, ADD_REDIRECT_RULE_FORMAT, inet_ntoa(ip_addr), bridge_ipaddr);
                    system(temp_buf);
                }
            }
        }
        /*check the client which will to be do auth check*/
        delay.tv_sec = CLATDM_LOOP_INTERVAL;
        clock_gettime(CLOCK_MONOTONIC, &now_time);
        client.ip4_addr=0;
        sem_lock();
        for(i=0; i<shm_ptr->client_num; i++)
        {
            if((shm_ptr->client[i].status==ADD_ALLOW_RULE)&&(shm_ptr->client[i].time_out>0)) //!!!!!!ADD_ALLOW_RULE!!!!!!!!!
            {
                if(shm_ptr->client[i].time_out>now_time.tv_sec)
                {
                    interval_sec=shm_ptr->client[i].time_out-now_time.tv_sec;
                    if(interval_sec<delay.tv_sec)
                    {
                        delay.tv_sec=interval_sec;
                        memcpy(&client, &(shm_ptr->client[i]), sizeof(client_info));
                    }
                }
                else
                {
                    delay.tv_sec=0;
                    memcpy(&client, &(shm_ptr->client[i]), sizeof(client_info));
                    break;
                }
            }
        }
        sem_unlock();
        if(delay.tv_sec !=0)
        { /*sleep*/
            delay.tv_usec = 0;
            select(0, NULL, NULL, NULL, &delay);
        }
        /*process time out client*/
        clock_gettime(CLOCK_MONOTONIC, &now_time);
        if((next_detect_time<=now_time.tv_sec)&&(get_arp_info()==0))
        {
            next_detect_time=now_time.tv_sec+DETECT_LEAVE_INTERVAL;
            
            sem_lock();
            for(i=0; i<shm_ptr->client_num; i++)
            {
                if(shm_ptr->client[i].status==AUTH_SUCCESSFUL)
                {
                    arp_found=false;
                    
                    for(k=0; k<client_arp_info.client_num; k++)
                    {
                        if((shm_ptr->client[i].ip4_addr==client_arp_info.client[k].ip4_addr)&&
                            (memcmp(shm_ptr->client[i].mac_addr, client_arp_info.client[k].mac_addr, 6)==0))
                        {
                            arp_found=true;
                            shm_ptr->client[i].detec_leave=0;
                        }
                    }
                    if(arp_found==false)
                        shm_ptr->client[i].detec_leave++;

                    if(shm_ptr->client[i].detec_leave>=NO_ARP_TIMES)
                    {
                        if(shm_ptr->client_num<MAX_CLIENTS_NUMBER)
                            memmove(&(shm_ptr->client[i]), &(shm_ptr->client[i+1]), sizeof(client_info));
                        /*shm_ptr->client_num==MAX_CLIENTS_NUMBER,don't do memmove*/
                        shm_ptr->client_num--;
                        i--;
                    }
                }
            }
            sem_unlock();
        }
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

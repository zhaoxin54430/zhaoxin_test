#ifndef __LIBSHMEM_H
#define __LIBSHMEM_H

#include <stdint.h>
#include <time.h>

#define SHMEM_SIZE 4096
#define MAX_CLIENTS_NUMBER 128
#define BRIDGE_NAME "br-lan"
#define ADD_REDIRECT_RULE_FORMAT  "iptables -t nat -A prerouting_lan_rule -s %s -p tcp -m multiport --dport 80,8080,443 -j DNAT --to-destination %s"
#define DELETE_REDIRECT_RULE_FORMAT  "iptables -t nat -D prerouting_lan_rule -s %s -p tcp -m multiport --dport 80,8080,443 -j DNAT --to-destination %s"
#define ADD_ALLOW_RULE_FORMAT  "iptables -t filter -A forwarding_lan_rule -s %s -j ACCEPT"
#define DELETE_ALLOW_RULE_FORMAT  "iptables -t filter -D forwarding_lan_rule -s %s -j ACCEPT"
//#define CLIENT_RECORD_RELEASE_TIME
#define CHECK_AUTH_TIMEOUT  180  //seconds
//#define DOMAIN_WHITE_LIST
#define CLATDM_PID_FILE "/tmp/clatdm_pid"


typedef enum
{
   SHMRET_SUCCESS              = 0,
   SHMRET_SEM_GET_ERROR       = 1,
   SHMRET_SEM_SETVAL_ERROR       = 2,
   SHMRET_SEM_LOCK_ERROR    = 3,
   SHMRET_SEM_UNLOCK_ERROR    = 4,
   SHMRET_SHM_GET_ERROR       = 5,
   SHMRET_SHM_MDT_ERROR       = 6,
   SHMRET_INVALID_ARGS     = 7,
}ShmRet;

typedef enum
{
    REDIRECT_RULE    = 1, /*client request ip successful, and had added redirect rule to firewall*/
    ADD_ALLOW_RULE , /*user had click the 'connect' button, router had add allow rule for the client*/
    AUTH_SUCCESSFUL , /*client had auth successful*/
    NOLIMIT_CLIENT, /*the client of assocation to ssid2 is no limit*/
}client_status;
/*if modify the client_info,need modify the MAX_CLIENTS_NUMBER, it make sure MAX_CLIENTS_NUMBER * sizeof(client_info) < SHMEM_SIZE -1 */
typedef struct clientInfo{
    unsigned char mac_addr[6];
    char detec_leave;
    uint32_t ip4_addr;
    client_status status;
    time_t time_out;/*the time for ADD_ALLOW_RULE or AUTH_SUCCESSFUL status*/
#ifdef CLIENT_RECORD_RELEASE_TIME    
    time_t release_time;/*accept the client's release request time*/
#endif
}client_info;

typedef struct allClientInfo{
    unsigned char client_num;
    client_info client[MAX_CLIENTS_NUMBER];
}all_client_info;

ShmRet Lock_init(char attachExisting);
ShmRet init_sem(void);
void Lock_cleanup(void);
void open_shm_log(char *proc_name);
void close_shm_log(void);
ShmRet sem_lock(void);
ShmRet sem_unlock(void);
ShmRet shm_mem_init(char attachExisting);
void *shm_mem_attach(void);
ShmRet shm_mem_detach(const void *shmp);
void shm_mem_cleanup(void);

#endif

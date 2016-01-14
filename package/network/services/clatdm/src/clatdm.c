/*
 *
 * Copyright 2012, St鑼卲han Kochen <stephan@kochen.nl>
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
#include "clatdm.h"


all_client_info *shm_ptr=NULL;

int main(int argc, char **argv)
{  
    void *ptr=NULL;
    client_info client;
    char attachExisting=false;
    FILE *flag_file=NULL;

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
        goto quit_mem;
    }
    shm_ptr=(all_client_info *)ptr;
    
    if(attachExisting==false)
    {
        sem_lock();
        /*only management process init the number*/
        shm_ptr->client_num=0;
        sem_unlock();
    }

    char lastnum=0;
    bool isAdd=false;
    while(true)
    {
        sleep(120);
        sem_lock();
        if(shm_ptr->client_num > lastnum)
        {
            memcpy(&client, &(shm_ptr->client[shm_ptr->client_num-1]), sizeof(client_info));
            lastnum=shm_ptr->client_num;
            isAdd=true;
        }
        sem_unlock();
        if(isAdd)
        {
            clatdm_error("add new client to share memory:%X", client.ip4_addr);
            isAdd=false;
        }
    }
    shm_mem_detach(ptr);
    shm_ptr=NULL;
    //shm_mem_cleanup();
    //Lock_cleanup();
    closelog();
    exit(0);

quit_lock:
    //Lock_cleanup();
    closelog();
    exit(1);
    
quit_mem:
    //shm_mem_cleanup();
    //Lock_cleanup();
    closelog();
    exit(1);    
} 
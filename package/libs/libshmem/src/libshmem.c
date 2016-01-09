#include <unistd.h>  
#include <sys/types.h>  
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <fcntl.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/sem.h> 
#include <syslog.h>
#include <errno.h>
#include "libshmem.h"


#define LOCK_SEMAPHORE_KEY 0x5ed7
#define SHARE_MEMORY_KEY 0x1ed7
#define SHM_INVALID_PID   -1
//#define LOG_OUTPUT_TO_SYSLOG

/** Linux kernel semaphore identifier. */
static int semid=-1;
/** Linux kernel share memory identifier. */
static int shmid=-1;

//static int lockOwner =SHM_INVALID_PID;
//static int shmOwner =SHM_INVALID_PID;

#ifdef LOG_OUTPUT_TO_SYSLOG
#define shmLog_error(args...) syslog(LOG_ERR, args);
#else
#define shmLog_error(args...)
#endif


ShmRet Lock_init(void)
{
   if ((semid = semget((key_t)LOCK_SEMAPHORE_KEY, 1, IPC_CREAT|0666)) == -1)
   {
      shmLog_error("semget failed, errno=%d", errno);
      return SHMRET_SEM_GET_ERROR;
   }
   return SHMRET_SUCCESS;
}
/*
 * only call once, the call proccess must first boot
 * (only management process call)
*/
ShmRet init_sem(void)  
{ 
    //union semun sem_union;  
  
    //sem_union.val = 1;  
    if(semctl(semid, 0, SETVAL, 1) == -1)  
   {
      shmLog_error("semctl setval 1 failed, errno=%d", errno);
      //Lock_cleanup();
      return SHMRET_SEM_SETVAL_ERROR;
   }
   return SHMRET_SUCCESS;
}

/*
 * only call once, the call proccess must last stop
 * (only management process call)
*/
void Lock_cleanup(void)
{
#if 0   
   if (lockOwner != SHM_INVALID_PID))
   {
      shmLog_error("lock is still held by %d, abort delete", lockOwner);
      return;
   }
#endif

   if(semctl(semid, 0, IPC_RMID) < 0)
   {
      shmLog_error("sem IPC_RMID failed, errno=%d", errno);
   }
   else
   {
      shmLog_error("Semid %d deleted.", semid);
      semid = -1;
   }
}

void open_shm_log(char *proc_name)
{
#ifdef LOG_OUTPUT_TO_SYSLOG
    int option = (proc_name==NULL)?(LOG_NDELAY|LOG_PID):(LOG_NDELAY);
    openlog(proc_name, option , 0);
#endif
}
void close_shm_log(void)
{
#ifdef LOG_OUTPUT_TO_SYSLOG
    closelog();
#endif
}

ShmRet sem_lock(void)
{  
    //p -1
    struct sembuf sem_b;  
    sem_b.sem_num = 0;  
    sem_b.sem_op = -1;//P()  
    sem_b.sem_flg = SEM_UNDO;  
    if(semop(semid, &sem_b, 1) == -1)  
    {  
        shmLog_error("sem_lock failed\n"); 
        return SHMRET_SEM_LOCK_ERROR;  
    }
    //lockOwner=getpid();
    return SHMRET_SUCCESS;  
}


ShmRet sem_unlock(void)
{  
    //v +1
    struct sembuf sem_b;  
    sem_b.sem_num = 0;  
    sem_b.sem_op = 1;//V()
    sem_b.sem_flg = SEM_UNDO;  
    if(semop(semid, &sem_b, 1) == -1)  
    {  
        shmLog_error("sem_unlock failed\n"); 
        return SHMRET_SEM_UNLOCK_ERROR;
    }
    //lockOwner=SHM_INVALID_PID;
    return SHMRET_SUCCESS;  
} 


ShmRet shm_mem_init(void)
{
    shmid = shmget((key_t)SHARE_MEMORY_KEY, (size_t)SHMEM_SIZE, 0666|IPC_CREAT);
    if(shmid == -1)
    {
        shmLog_error("shmget failed, errno=%d", errno);
        return SHMRET_SHM_GET_ERROR;
    }
    return SHMRET_SUCCESS;
}
void *shm_mem_attach(void)
{
    void *shmp=NULL;
    shmp = shmat(shmid,NULL,0);
    if(shmp==(void *)(-1))
    {
        shmLog_error("shmat failed, errno=%d", errno);
    }
    //shmOwner=getpid();
    return shmp;
}
ShmRet shm_mem_detach(const void *shmp)
{
    int dtRet=-1;

    if(shmp==NULL)
    {
        shmLog_error("shmdt failed, shmp==NULL ");
        return SHMRET_INVALID_ARGS;
    }
    dtRet = shmdt(shmp);
    if(dtRet == -1)
    {
        shmLog_error("shmdt failed, errno=%d", errno);
        return SHMRET_SHM_MDT_ERROR;
    }
    //shmOwner=SHM_INVALID_PID;
    return SHMRET_SUCCESS;
}
/*
 * only call once
 * (only management process call)
*/
void shm_mem_cleanup(void)
{
    if(shmctl( shmid, IPC_RMID, NULL )== -1)
    {
        shmLog_error("shm IPC_RMID failed, errno=%d", errno);
    }
    else
    {
        shmLog_error("shmid %d deleted.", shmid);
        shmid = -1;
    }
}

#include <stdint.h>
#include <time.h>

#define SHMEM_SIZE 4096

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

ShmRet Lock_init(void);
ShmRet init_sem(void);
void Lock_cleanup(void);
void open_shm_log(char *proc_name);
void close_shm_log(void);
ShmRet sem_lock(void);
ShmRet sem_unlock(void);
ShmRet shm_mem_init(void);
void *shm_mem_attach(void);
ShmRet shm_mem_detach(const void *shmp);
void shm_mem_cleanup(void);
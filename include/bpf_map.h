#ifndef __BPF_MAP_H__
#define __BPF_MAP_H__

#define EVENT_MSG_TYPE_PROCESS_CREATE 1
#define EVENT_MSG_TYPE_PROCESS_EXIT   2
#define EVENT_MSG_TYPE_PROCESS_KILL   3

typedef struct
{
    uint32_t pid;
    uint32_t ppid;
    int exit_code;
    int exit_sig;
    char cmd[256];
    char env[128];
} BPF_MAP_ITEM_PROCESS;

typedef struct
{
    uint32_t pid_sender;
    uint32_t pid_target;
    uint32_t tid_target;
    int sig;
} BPF_MAP_ITEM_KILL;

typedef struct
{
    int type;
    int size;
    uint8_t data[0];
} BPF_MAP_ITEM_EVENT;

#endif /* __BPF_MAP_H__ */


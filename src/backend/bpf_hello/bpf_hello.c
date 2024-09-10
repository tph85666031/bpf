#include "vmlinux.h"
#define BPF_NO_GLOBAL_DATA  //4.19不支持全局变量
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_map.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, BPF_MAP_ITEM_PROCESS);
    __uint(max_entries, 10240);
} bpf_map_process_info SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, uint32_t);//针对BPF_MAP_TYPE_PERF_EVENT_ARRAY，只能是4字节的数据类型
    __type(value, uint32_t);//针对BPF_MAP_TYPE_PERF_EVENT_ARRAY，只能是4字节的数据类型
} bpf_map_process_event SEC(".maps");

char LICENSE[] SEC("license") = "Dual BSD/GPL";

__always_inline int com_bpf_strncmp(const char* a, uint8_t a_size, const char* b)
{
    if(a == NULL || b == NULL || a_size == 0)
    {
        return 0;
    }

    //uos 4.19内核不支持for,也不支持bpf_strncmp
#pragma unroll
    for(uint8_t i = 0; i < a_size; i++)
    {
        if(a[i] != b[i])
        {
            return a[i] - b[i];
        }
        if(a[i] == '\0' || b[i] == '\0')
        {
            return a[i] - b[i];
        }
    }
    return 0;
}

///sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog_execv_enter(struct trace_event_raw_sys_enter* ctx)
{
    pid_t pid = (pid_t)bpf_get_current_pid_tgid();
    {
        BPF_MAP_ITEM_PROCESS item_tmp;//4.19不支持全局变量
        __builtin_memset(&item_tmp, 0, sizeof(item_tmp));
        bpf_map_update_elem(&bpf_map_process_info, &pid, &item_tmp, BPF_ANY);
    }
    BPF_MAP_ITEM_PROCESS* item = bpf_map_lookup_elem(&bpf_map_process_info, &pid);
    if(item == NULL)
    {
        return 0;
    }

    struct task_struct* task_parent = NULL;
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read(&task_parent, sizeof(task_parent), &task->parent);
    bpf_probe_read(&item->ppid, sizeof(item->ppid), &task_parent->pid);
    item->pid = pid;
    //bpf_printk("item->pid=%u\n", item->pid);//4.19不支持libbpf1.0+的bpf_printk

    //取进程全路径,数据存于map以避开存于堆栈中的512限制
    int offset = bpf_probe_read_user_str(item->cmd, sizeof(item->cmd), (void*)ctx->args[0]);
    if(offset <= 0 || offset >= sizeof(item->cmd))
    {
        bpf_map_delete_elem(&bpf_map_process_info, &item->pid);
        return 0;
    }

    //取参数
    const char** argv = (const char**)ctx->args[1];
    if(argv != NULL)
    {
#pragma unroll
        for(int i = 1; i < 16; i++)
        {
            char* p;
            if(bpf_probe_read(&p, sizeof(p), &argv[i]) != 0)
            {
                break;
            }
            if(offset >= 1 && offset <= sizeof(item->cmd))
            {
                item->cmd[offset - 1] = ' ';
            }
            if(offset < 0 || offset >= sizeof(item->cmd) / 2)
            {
                break;
            }
            int ret = bpf_probe_read_user_str(&item->cmd[offset], sizeof(item->cmd) / 2, p);
            if(ret <= 0)
            {
                break;
            }
            offset += ret;
        }

        if(offset > 0 && offset <= sizeof(item->cmd))
        {
            item->cmd[offset - 1] = '\0';
        }
    }

    //取环境变量
    const char** envp = (const char**)ctx->args[2];
    if(envp != NULL)
    {
        offset = 0;
#pragma unroll
        for(int i = 0; i < 16; i++)
        {
            char* p;
            if(bpf_probe_read(&p, sizeof(p), &envp[i]) != 0)
            {
                break;
            }
            if(offset >= 1 && offset <= sizeof(item->env))
            {
                item->env[offset - 1] = ';';
            }
            if(offset < 0 || offset >= sizeof(item->env) / 2)
            {
                break;
            }
            int ret = bpf_probe_read_user_str(&item->env[offset], sizeof(item->env) / 2, p);
            if(ret <= 0)
            {
                break;
            }
            offset += ret;
        }
        if(offset > 0 && offset <= sizeof(item->env))
        {
            item->env[offset - 1] = '\0';
        }
    }

    //存储path供exit时使用
    if(bpf_map_update_elem(&bpf_map_process_info, &item->pid, item, BPF_ANY) == 0)
    {
        //事件通知
        uint8_t buf[sizeof(BPF_MAP_ITEM_EVENT) + sizeof(BPF_MAP_ITEM_PROCESS)];
        BPF_MAP_ITEM_EVENT* item_event = (BPF_MAP_ITEM_EVENT*)buf;
        item_event->type = EVENT_MSG_TYPE_PROCESS_CREATE;
        item_event->size = sizeof(BPF_MAP_ITEM_PROCESS);
        __builtin_memcpy(item_event->data, item, sizeof(BPF_MAP_ITEM_PROCESS));
        bpf_perf_event_output(ctx, &bpf_map_process_event, BPF_F_CURRENT_CPU, buf, sizeof(buf));
    }
    else
    {
        bpf_map_delete_elem(&bpf_map_process_info, &item->pid);
    }
    return 0;
}

///sys/kernel/debug/tracing/events/sched/sched_process_exit/format
SEC("tracepoint/sched/sched_process_exit")
int bpf_prog_process_exit(struct trace_event_raw_sched_process_template* ctx)
{
    pid_t pid = (pid_t)bpf_get_current_pid_tgid();
    BPF_MAP_ITEM_PROCESS* item = bpf_map_lookup_elem(&bpf_map_process_info, &pid);
    if(item != NULL)
    {
        struct task_struct* task = (struct task_struct*)bpf_get_current_task();
        bpf_probe_read(&item->exit_code, sizeof(item->exit_code), &task->exit_code);
        item->exit_sig = item->exit_code & 0xFF;
        item->exit_code = item->exit_code >> 8;
        //事件通知
        uint8_t buf[sizeof(BPF_MAP_ITEM_EVENT) + sizeof(BPF_MAP_ITEM_PROCESS)];
        BPF_MAP_ITEM_EVENT* item_event = (BPF_MAP_ITEM_EVENT*)buf;
        item_event->type = EVENT_MSG_TYPE_PROCESS_EXIT;
        item_event->size = sizeof(BPF_MAP_ITEM_PROCESS);
        __builtin_memcpy(item_event->data, item, sizeof(BPF_MAP_ITEM_PROCESS));
        bpf_perf_event_output(ctx, &bpf_map_process_event, BPF_F_CURRENT_CPU, buf, sizeof(buf));
        bpf_map_delete_elem(&bpf_map_process_info, &pid);
    }
    return 0;
}

///sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
SEC("tracepoint/syscalls/sys_enter_openat")
int bpf_prog_openat(struct trace_event_raw_sys_enter* ctx)
{
    char* filename = (char*)ctx->args[1];
    char path[256];
    bpf_probe_read(path, sizeof(path), filename);
    if(com_bpf_strncmp("/data/1.txt", sizeof("/data/1.txt"), path) == 0)
    {
        //bpf_printk("path=%s\n", path);
        __builtin_memcpy(path, "/1.txt", sizeof("/1.txt"));
        long ret = bpf_probe_write_user((char*)ctx->args[1], path, sizeof("/1.txt"));
        bpf_probe_read(path, sizeof(path), (char*)ctx->args[1]);
        bpf_printk("path=%s,ret=%ld\n", path, ret);
    }
    return 0;
}

SEC("ksyscall/kill")
int BPF_KPROBE(bpf_kill_enter, pid_t* pid, pid_t tid, int sig)
{
    if(sig == 0)
    {
        return 0;
    }
    //bpf_override_return(ctx, -13);//UOS内核没有设置CONFIG_BPF_KPROBE_OVERRIDE,bpf_override_return无法使用
    uint8_t buf[sizeof(BPF_MAP_ITEM_EVENT) + sizeof(BPF_MAP_ITEM_KILL)];

    BPF_MAP_ITEM_EVENT* item_event = (BPF_MAP_ITEM_EVENT*)buf;
    item_event->type = EVENT_MSG_TYPE_PROCESS_KILL;
    item_event->size = sizeof(BPF_MAP_ITEM_KILL);

    BPF_MAP_ITEM_KILL* data = (BPF_MAP_ITEM_KILL*)item_event->data;
    data->pid_sender = (pid_t)bpf_get_current_pid_tgid();
    data->sig = sig;
    data->tid_target = tid;
    if(bpf_probe_read(&data->pid_target, sizeof(data->pid_target), pid) == 0)
    {
        bpf_perf_event_output(ctx, &bpf_map_process_event, BPF_F_CURRENT_CPU, buf, sizeof(buf));
    }
    return 0;
}


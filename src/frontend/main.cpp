#include <cerrno>
#include <vector>
#include <sys/resource.h>
#include "bpf/libbpf.h"
#include "bpf_map.h"

class BpfLoader
{
public:
    BpfLoader()
    {
        bpf_obj = NULL;
        struct rlimit rlim_new =
        {
            .rlim_cur = RLIM_INFINITY,
            .rlim_max = RLIM_INFINITY,
        };

        setrlimit(RLIMIT_MEMLOCK, &rlim_new);
    }
    virtual ~BpfLoader()
    {
        unload();
    }

    int load(const char* path, const char* btf = NULL)
    {
        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        LIBBPF_OPTS(bpf_object_open_opts, opt);
        opt.btf_custom_path = btf;
        bpf_obj = bpf_object__open_file(path, btf == NULL ? NULL : &opt);
        if(bpf_obj == NULL)
        {
            printf("failed to open bpf file:%s\n", path);
            return -1;
        }

        if(bpf_object__load(bpf_obj) != 0)
        {
            printf("failed to load prog: %s,errno=%d\n", path, errno);
            return -2;
        }

        struct bpf_program* bpf_prog = NULL;
        bpf_object__for_each_program(bpf_prog, bpf_obj)
        {
            struct bpf_link* link = bpf_program__attach(bpf_prog);
            if(link == NULL)
            {
                printf("failed to attach bpf_prog:%s:%s\n", path, bpf_program__name(bpf_prog));
                return -3;
            }
            bpf_links.push_back(link);
        }
        return 0;
    }

    void unload()
    {
        for(size_t i = 0; i < bpf_links.size(); i++)
        {
            if(bpf_links[i] != NULL)
            {
                bpf_link__destroy(bpf_links[i]);
            }
        }
        if(bpf_obj != NULL)
        {
            bpf_object__close(bpf_obj);
        }
    }

    void loop()
    {
        if(bpf_obj == NULL)
        {
            getchar();
            return;
        }
        int fd_map_event = bpf_object__find_map_fd_by_name(bpf_obj, "bpf_map_process_event");
        struct perf_buffer* pb = perf_buffer__new(fd_map_event, 64, EventCallbackProcess, EventCallbackLostProcess, NULL, NULL);
        if(pb == NULL)
        {
            getchar();
            return;
        }
        while(perf_buffer__poll(pb, 100) >= 0)
        {
        }
        perf_buffer__free(pb);
    }
private:
    static void EventCallbackProcess(void* ctx, int cpu, void* data, uint32_t size)
    {
        if(data == NULL || size <= 0)
        {
            printf("arg incorrect,data=%p,size=%u\n", data, size);
            return;
        }
        BPF_MAP_ITEM_EVENT* item_event = (BPF_MAP_ITEM_EVENT*)data;
        if(item_event->type == 1)
        {
            BPF_MAP_ITEM_PROCESS* data = (BPF_MAP_ITEM_PROCESS*)item_event->data;
            printf("cpu=%d,pid=%u,ppid=%u,cmd=%s,status=created\n", cpu, data->pid, data->ppid, data->cmd);
        }
        else if(item_event->type == 2)
        {
            BPF_MAP_ITEM_PROCESS* data = (BPF_MAP_ITEM_PROCESS*)item_event->data;
            printf("cpu=%d,pid=%u,ppid=%u,cmd=%s,status=exit,code=%d,sig=%d\n", cpu, data->pid, data->ppid, data->cmd, data->exit_code, data->exit_sig);
        }
        else if(item_event->type == 3)
        {
            BPF_MAP_ITEM_KILL* data = (BPF_MAP_ITEM_KILL*)item_event->data;
            printf("%u try to kill %u:%u with %d\n", data->pid_sender, data->pid_target, data->tid_target, data->sig);
        }
    }
    static void EventCallbackLostProcess(void* ctx, int cpu, __u64 count)
    {
        printf("!!!event lost[%llu]!!!\n", count);
    }
private:
    std::vector<struct bpf_link*> bpf_links;
    struct bpf_object* bpf_obj;
};

int main(int argc, const char** argv)
{
    BpfLoader loader;
    loader.load(argv[1], argv[2]);
    loader.loop();
    return 0;
}


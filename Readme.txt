1：4.19内核使用libbpf1.0+版本来加载bpf kernel
bpf load时手动指定btf文件即可

2：vmlinux没有btf信息
需手动编译对应版本的内核vmlinux(或者从https://github.com/aquasecurity/btfhub-archive 下载对应内核版本的btf)
使用pahole --btf_encode_detached linux_kernel.btf vmlinux生成linux_kernel.btf文件
由于linux_kernel.btf文件较大，可以使用bpftool gen min_core_btf linux_kernel.btf  linux_kernel_lite.btf path_to_bpf_kernel_module.o 来构建精简的btf文件

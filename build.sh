#!/bin/bash

BUILD_LIBBPF="false"
BUILD_FRONTEND="false"
BUILD_BACKEND="false"

show_usage()
{
    echo "Usage:  -b build backend"
    echo "        -f build frontend"
    echo "        -h show help"
    echo ""
    exit -1
}

while getopts 'bflh' OPT; do
    case $OPT in
    b)
        BUILD_BACKEND="true";;
    f)
        BUILD_FRONTEND="true";;
    l)
        BUILD_LIBBPF="true";;
    h)
        show_usage;;
    ?)
        show_usage
    esac
done
shift $(($OPTIND - 1))

ARCH=`uname -m`
if [ x"$ARCH"==x"x86_64" ];then
    ARCH="x86"
fi

if [ x"$BUILD_LIBBPF" == x"true" ];then
    pushd ./3rd/libbpf-latest/src
	echo "  using "$(realpath ..)
	rm -rf build
	mkdir build
	BUILD_STATIC_ONLY=y OBJDIR=build PREFIX=/ LIBDIR=lib DESTDIR=../../../out/ make install
	rm -rf build
	popd
fi

if [ x"$BUILD_BACKEND" == x"true" ];then
    mkdir -pv ./out/bin
    for PROG_PATH in ./src/backend/*
    do
        PROG_NAME=`basename $PROG_PATH`
        if [ ! -d ${PROG_PATH} ];then
            continue
        fi
        clang -Wall -O2 -g -target bpf -D__TARGET_ARCH_${ARCH} -I./src/backend/${PROG_NAME} -I./src/backend -I./include -I./out/include -c $PROG_PATH/${PROG_NAME}.c -o ./out/bin/${PROG_NAME}.o
    done
fi

if [ x"$BUILD_FRONTEND" == x"true" ];then
    mkdir -pv ./out/bin
    rm -rf build
    mkdir build
    pushd build
    cmake ../
    make -j4 && make install
	popd
fi

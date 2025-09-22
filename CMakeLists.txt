cmake_minimum_required(VERSION 4.0)
project(IN4230_Oblig1 C)

set(CMAKE_C_STANDARD 23)

add_executable(IN4230_Oblig1
        src/mipd.c
        src/common.c
        src/common.h
        src/mip.h
        src/mip_arp.h
        src/mip.c
        src/ping_client.c
        src/ping_sever.c
        src/mip_arp.c
        src/linked_list.c
        src/linked_list.h
        src/ether.h
        src/pdu.h
        src/pdu.c)

//
// Created by acm on 3/10/18.
//

#ifndef JUDGETEST_WHITELIST_H
#define JUDGETEST_WHITELIST_H

#include <syscall.h>
#include <iostream>

#define Allow(id) SyscallLimit((id),
#define calls(t)  (t))
#define INF -1

char syscall_list[400][64];
int max_syscall_id;
int syscall_cnt[400];

short white_list[512];

struct SyscallLimit {
    short syscall_id, times;
    SyscallLimit(short id, short t): syscall_id(id), times(t) {}
};

SyscallLimit cpp_limit[] = {
        Allow (SYS_read)             calls (INF),
        Allow (SYS_write)            calls (INF),
        Allow (SYS_execve)           calls (1),
        Allow (SYS_time)             calls (INF),
        Allow (SYS_access)           calls (1),
        Allow (SYS_brk)              calls (INF),
        Allow (SYS_readlink)         calls (1),
        Allow (SYS_sysinfo)          calls (INF),
        Allow (SYS_uname)            calls (INF),
        Allow (SYS_fstat64)          calls (INF),
        Allow (SYS_set_thread_area)  calls (INF),
        Allow (SYS_exit_group)       calls (1)
};

void initSyscallList() {
    FILE *fd = fopen("./syscall.txt", "r");
    if(!fd) {
        std::cerr << "Open syscall.txt failed.\n";
        return;
    }
    max_syscall_id = 0;
    char str[64];
    int id;
    while(~fscanf(fd, "%s%d", str, &id)) {
        strcpy(syscall_list[id], str);
        max_syscall_id = max_syscall_id < id? id : max_syscall_id;
    }
}

void outputSyscall() {
    std::clog << "------------- SYSCALL ---------------\n";
    for(int i = 0; i < max_syscall_id; i++) {
        if(syscall_cnt[i]) {
            std::clog << syscall_list[i] << "(id: " << i << ") called " << syscall_cnt[i] << " times.\n";
        }
    }
    std::clog << "----------- SYSCALL END -------------\n";
}

void initWhiteList() {
    memset(white_list, 0, sizeof(white_list));
    SyscallLimit *t = cpp_limit;
    int size = sizeof(cpp_limit)/sizeof(SyscallLimit);
    for(int i = 0; i < size; i++) {
        white_list[t[i].syscall_id] = t[i].times;
    }
}

void outputWhiteList() {
    std::clog << "---------- SYSCALL LIMIT -------------\n";
    for(int i = 0; i < max_syscall_id; i++) {
        if(white_list[i]) {
            std::clog << syscall_list[i] << " can be called " << white_list[i] << " times.\n";
        }
    }
    std::clog << "--------------------------------------\n";
}

bool isValidSyscall(int syscall_id) {
    static bool insyscall = true;

    insyscall = !insyscall;
    if(insyscall) {
        std::clog << "Enter system call: " << syscall_list[syscall_id] << "\n";
        if(white_list[syscall_id] == INF) {
            std::clog << syscall_list[syscall_id] << " can be called INF times.\n";
            return true;
        } else if(white_list[syscall_id] > 0) {
            white_list[syscall_id]--;
            std::clog << syscall_list[syscall_id] << " can be called "<< white_list[syscall_id] <<" times.\n";
            return true;
        } else {
            std::clog << syscall_list[syscall_id] << " can't be called any more!\n";
            return false;
        }
    } else {
        std::clog << "Leave system call: " << syscall_list[syscall_id] << "\n";
        return true;
    }
}

#endif //JUDGETEST_WHITELIST_H

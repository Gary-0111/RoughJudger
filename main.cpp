/*
 * Author: Felix
 *
 * usage:
 *      ./Judge [OPTIONS]
 *
 * options:
 *      -l      The solution's language [C|C++|Java]
 *      -p      Problem ID.
 *      -t      Time limit. Millisecond by default.
 *      -m      Memory limit. Kilo-Bytes by default. [K|M]
 */

#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <cstring>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/stat.h>
#include "Time.h"
#include "whiteList.h"

using namespace std;
const char *datadir = "./data/";
const char *tempdir = "temp";

enum Result {
    Result_Running,             // := 0
    Result_Accepted,            // := 1
    Result_WrongAnswer,         // := 2
    Result_TimeLimitExceed,     // := 3
    Result_MemoryLimitExceed,   // := 4
    Result_OutputLimitExceed,   // := 5
    Result_RuntimeError,        // := 6
    Result_PresentationError,   // := 7
    Result_CompilationError,    // := 8
    Result_SystemError,         // := 9
    Result_DangerouCode         // := 10
};

const char *result_str[] = {
        "Running",
        "Accepted",
        "Wrong Answer",
        "Time Limit Exceed",
        "Memory Limit Exceed",
        "Output Limit Exceed",
        "Runtime Error",
        "Presentation Error",
        "Compilation Error",
        "System Error",
        "Dangerous Code"
};

enum Language {
    Lang_Unknown,
    Lang_C,
    Lang_Cpp,
    Lang_Java
};

struct Options {
    Language lang;
    string data_dir;
    const char *judge_user_name = "judger";
    unsigned long time_limit;                   // ms
    unsigned long memory_limit;                 // KB
};

Options opt;
Result result;

Language getLang(char *lang) {
    if(strcmp(lang, "C") == 0) return Lang_C;
    else if(strcmp(lang, "C++") == 0) return Lang_Cpp;
    else if(strcmp(lang, "Java") == 0) return Lang_Java;
    return Lang_Unknown;
}

void parseParameter(int argc, char *argv[]) {
    int ch;
    while((ch = getopt(argc, argv, "l:p:t:m:")) != -1) {
        switch(ch) {
            case 'l':
                opt.lang = getLang(optarg);
                break;
            case 'p':
                opt.data_dir = optarg;
                break;
            case 't':
                sscanf(optarg, "%lu", &opt.time_limit);
                break;
            case 'm':
                sscanf(optarg, "%lu", &opt.memory_limit);
                break;
            case '?':
                cerr << "Invalid options.";
                break;
            default:
                break;
        }
    }
}

void outputResult() {
    clog << "#################### RESULT ####################\n";
    clog << result_str[result] << "\n";
}

int compile() {
    int ret = 0;
    pid_t pid;
    while((pid = fork()) == -1) ;
    if(pid == 0) {
        const char * const cmd[20] = {"g++", "Main.cpp", "-o", "Main", "--static"};
        execvp(cmd[0], (char* const*)cmd);
        cerr << cmd[0] << " error: " << errno << "\n";
        ret = -1;
    } else {
        int status;
        wait(&status);
        if(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
            clog << "Successful compile!\n";
        } else {
            result = Result_CompilationError;
            cerr << "Compile user's code failed.\n";
            outputResult();
            exit(1);
        }
    }
    return ret;
}

void setLimit()
{
    rlimit lim;
    //时间限制
    lim.rlim_cur = (opt.time_limit + 999) / 1000;
    lim.rlim_max = lim.rlim_cur;
    if(setrlimit(RLIMIT_CPU, &lim) < 0) {
        cerr << "Set rlimit error.\n";
        return;
    }
}

void alarm(int which, int milliseconds) {
    struct itimerval it;

    it.it_value.tv_sec = milliseconds / 1000;
    it.it_value.tv_usec = (milliseconds % 1000) * 1000;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;

    setitimer(which, &it, NULL);
}

void timeoutHandler(int signo) {
    switch (signo) {
        case SIGPROF:
            cerr << "Timeout!\n";
            exit(-1);
        default:
            break;
    }
}

unsigned long getMemory(pid_t pid) {
    char buffer[256];
    sprintf(buffer, "/proc/%d/status", pid);
    FILE* fp = fopen(buffer, "r");
    if (fp == NULL) {
        cerr << "Open " << buffer << " failed.\n";
        exit(1);
    }
    unsigned long vmPeak = 0, vmSize = 0, vmExe = 0, vmLib = 0, vmStack = 0;
    while (fgets(buffer, 32, fp)) {
        if (!strncmp(buffer, "VmPeak:", 7)) {
            sscanf(buffer + 7, "%lu", &vmPeak);
        } else if (!strncmp(buffer, "VmSize:", 7)) {
            sscanf(buffer + 7, "%lu", &vmSize);
        } else if (!strncmp(buffer, "VmExe:", 6)) {
            sscanf(buffer + 6, "%lu", &vmExe);
        } else if (!strncmp(buffer, "VmLib:", 6)) {
            sscanf(buffer + 6, "%lu", &vmLib);
        } else if (!strncmp(buffer, "VmStk:", 6)) {
            sscanf(buffer + 6, "%lu", &vmStack);
        }
    }
    fclose(fp);
    if (vmPeak) {
        vmSize = vmPeak;
    }
    return vmSize - vmExe - vmLib - vmStack;
}

bool isInputFile(const char *filename) {
    return strcmp(filename + strlen(filename) - 3, ".in") == 0;
}

void compareUntilNonspace(FILE *&fd_std, int &ch_std, FILE *&fd_usr, int &ch_usr, Result &ret) {
    while(isspace(ch_std) || isspace(ch_usr)) {
        if(ch_std != ch_usr) {
            // Deal with the files from Windows.
            // The end-of-line is CRLF(\r\n) in Windows, LF(\n) in *nix and CR("\r") in Mac.
            if(ch_std == '\r' && ch_usr == '\n') {
                ch_std = fgetc(fd_std);
                if(ch_std != ch_usr) {
                    ret = Result_PresentationError;
                }
            } else {
                ret = Result_PresentationError;
            }
        }
        if(isspace(ch_std)) ch_std = fgetc(fd_std);
        if(isspace(ch_usr)) ch_usr = fgetc(fd_usr);
        if(ret == Result_PresentationError) return;
    }
}

Result compareOutput(const char *std_file, const char *usr_file) {
    Result ret = Result_Running;
    FILE *fd_std = fopen(std_file, "r");
    FILE *fd_usr = fopen(usr_file, "r");

    if(!fd_std) {
        cerr << "Can not open standard file!\n" << std_file << ": No such file.\n";
        return Result_RuntimeError;
    }
    if(!fd_usr) {
        cerr << "Can not open user's file!\n" << usr_file << ": No such file.\n";
        return Result_RuntimeError;
    }

    bool isEnd = false;
    int ch_std = fgetc(fd_std);
    int ch_usr = fgetc(fd_usr);
    while(ret == Result_Running) {
        if(isEnd) break;
        compareUntilNonspace(fd_std, ch_std, fd_usr, ch_usr, ret);
        if(ret == Result_PresentationError) break;
        while((!isspace(ch_std)) && (!isspace(ch_usr))) {
            if(ch_std == EOF && ch_usr == EOF) {
                isEnd = true;
                break;
            }
            if(ch_std != ch_usr) {
                ret = Result_WrongAnswer;
                break;
            }
            ch_std = fgetc(fd_std);
            ch_usr = fgetc(fd_usr);
        }
    }

    if(fd_std) fclose(fd_std);
    if(fd_usr) fclose(fd_usr);

    return ret;
}

int removeTempDir() {
    DIR *dir;
    dirent *ptr;
    if(chdir(tempdir)) {
        cerr << "Change directory failed.\n";
        return -1;
    }
    if((dir = opendir(".")) == NULL) {
        cerr << "Open directory failed.\n" << tempdir << ": No such directory.\n";
        return -1;
    }
    while((ptr = readdir(dir)) != NULL) {
        if(strcmp(".", ptr->d_name) == 0 || strcmp("..", ptr->d_name) == 0) continue;
        if(remove(ptr->d_name)) {
            cerr << "Remove file failed.\n" << ptr->d_name << "\n";
            break;
        }
    }
    closedir(dir);
    if(chdir("..")) {
        cerr << "Change directory failed.\n";
        return -1;
    }
    if(rmdir(tempdir)) {
        cerr << "Remove directory failed.\n";
        return -1;
    }
    return 0;
}

int run(const char *dirpath) {
    int ret = 0;
    pid_t pid = -1;

    DIR *dir;
    dirent *ptr;
    if((dir = opendir(dirpath)) == NULL) {
        cerr << "Open directory failed.\n" << dirpath << ": No such directory.\n";
        exit(1);
    }

    passwd* judge_user = getpwnam(opt.judge_user_name);
    if(judge_user == NULL) {
        cerr << "No such user: " << opt.judge_user_name << "\n";
        exit(1);
    }

    if(mkdir(tempdir, 0777)) {
        cerr << "Create directory failed.\n";
        exit(1);
    }

    char tmpName[1024];
    unsigned long memUsed = 0;
    Time timeUsed, timeLimit((timeval){opt.time_limit/1000, (opt.time_limit%1000) * 1000});

    // Traverse all input files in dirpath.
    while((result == Result_Running || result == Result_PresentationError) && (ptr = readdir(dir)) != NULL) {

        if(strcmp(".", ptr->d_name) == 0 || strcmp("..", ptr->d_name) == 0) continue;
        if(!isInputFile(ptr->d_name)) continue;

        int len = strlen(ptr->d_name);
        strcpy(tmpName, ptr->d_name);
        tmpName[len - 3] = '\0';

        char std_input_file[256], std_output_file[256], usr_output_file[256];
        strcpy(std_input_file, (string(dirpath) + "/" + ptr->d_name).c_str());
        strcpy(std_output_file, (string(dirpath) + "/" + tmpName + ".out").c_str());
        strcpy(usr_output_file, ("temp/" + string(tmpName) + ".out").c_str());

        clog << "\n************** Test case #" << tmpName << " *****************\n";
        clog << "standard input file:   " << std_input_file << "\n";
        clog << "standard output file:  " << std_output_file << '\n';
        clog << "user's output file:    " << usr_output_file << '\n';

        while((pid = fork()) == -1) ;
        if(pid == 0) {

            // I/O redirect.
            freopen(std_input_file, "r", stdin);
            freopen(usr_output_file, "w", stdout);

            // Set euid.
            if(seteuid(judge_user->pw_uid) != EXIT_SUCCESS) {
                cerr << "Set euid failed.\n";
            }
            clog << "The Judger's id is " << judge_user->pw_uid << "\n";
            clog << "The child process's uid is " << getuid() << "\n";
            clog << "The child process's euid is " << geteuid() << "\n";

            // Trace the child process.
            ptrace(PTRACE_TRACEME, 0, NULL, NULL);

            // Set the resources limits.
            setLimit();

            // signal(SIGPROF, timeoutHandler);
            // alarm(ITIMER_REAL, 1000);

            // Execute the user's program.
            execvp("./Main", NULL);

            cerr << "execv error: " << errno << '\n';
            ret = -1;
        } else {
            // 监控子进程的系统调用,并监测子进程使用的内存及时间
            int status;
            memset(syscall_cnt, 0, sizeof(syscall_cnt));
            initWhiteList();
            outputWhiteList();
            rusage rused;
            while (true) {
                wait4(pid, &status, 0, &rused);

                // Get the system call ID.

                int syscall_id = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL);
                syscall_cnt[syscall_id]++;

                // Check if the child process is terminated normally.
                if(WIFEXITED(status)) {
                    outputSyscall();
                    clog << "Userexe was normally terminated.\n";
                    result = compareOutput(std_output_file, usr_output_file);

                    break;
                }

                // Check if the child process is TLE, RE or OLE.
                if(WIFSIGNALED(status) ||
                   (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP))
                {
                    int signo = 0;
                    if(WIFSIGNALED(status))
                        signo = WTERMSIG(status);
                    else
                        signo = WSTOPSIG(status);

                    switch(signo){
                        //TLE
                        case SIGXCPU:
                        case SIGKILL:
                        case SIGPROF:
                            result = Result_TimeLimitExceed;
                            break;

                        //OLE
                        case SIGXFSZ:
                            break;

                        // RE
                        case SIGSEGV:
                        case SIGABRT:
                        default:
                            result = Result_RuntimeError;
                            break;
                    }
                    ptrace(PTRACE_KILL, pid);
                    outputSyscall();
                    clog << "Userexe was killed! The terminated signal is: " << signo << "\n";
                    if(result == Result_TimeLimitExceed) timeUsed = timeLimit;
                    break;
                }

                // Check if the system call is valid.
                if(!isValidSyscall(syscall_id)) {
                    clog << "The child process trys to call a limited system call: " << syscall_list[syscall_id] << "\n";
                    ptrace(PTRACE_KILL, pid);
                    result = Result_DangerouCode;
                    break;
                }

                // Check if the child process is MLE.
                memUsed = max(memUsed, getMemory(pid));
                if(memUsed > opt.memory_limit) {
                    ptrace(PTRACE_KILL, pid);
                    memUsed = opt.memory_limit;
                    result = Result_MemoryLimitExceed;
                    break;
                }

                // Continue the child process until next time it calls a system call.
                ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            }

            //
            if(result == Result_Running || result == Result_PresentationError)
                timeUsed = timeUsed + Time(rused.ru_stime) + Time(rused.ru_utime);
            if(timeLimit < timeUsed) {
                result = Result_TimeLimitExceed;
                timeUsed = timeLimit;
            }

        }
    }

    if(pid > 0) {
        if(result == Result_Running) result = Result_Accepted;
        if(removeTempDir()) {
            exit(-1);
        }
        outputResult();
        clog << "Used Time: " << timeUsed << "    Used Memory: " << memUsed << "KB\n";
    }

    closedir(dir);
    return ret;
}

int main(int argc, char *argv[]) {

    parseParameter(argc, argv);
    cout << opt.lang << " " << opt.data_dir << " " << opt.time_limit << " " << opt.memory_limit << '\n';
    compile();

    initSyscallList();

    result = Result_Running;
    run((datadir + opt.data_dir).c_str());

    //clog << sizeof(cpp_limit)/sizeof(SyscallLimit) << "\n";
    return 0;
}
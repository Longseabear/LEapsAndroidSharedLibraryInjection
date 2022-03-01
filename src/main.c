// code ref: https://teamcrak.tistory.com/378
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/wait.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <asm/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>

#define SYSCALL_REGISTER(r)     r.regs[8]
#define RESULT_REGISTER(r)      r.regs[0]
#define IP_REGISTER(r)          r.regs[12]
#define MAX_BUFFER_LEN 1000


const char* zygote64_identifier = "/system/bin/app_process64";
const char* EXTRA_ENVIRONMENT = "LD_PRELOAD=/system/lib64/libmy_lib.so"; // 37
long internal_ptrace(int, pid_t, void *, void *);
#define PTRACE(r, p, a, d) internal_ptrace(r, p, a, d)
#define MAX_PROC_PID 65536

int init_pid = 1;


int finish(int pid){
    if (pid != 0){
        if(PTRACE(PTRACE_DETACH, pid, 0, 0) < 0){
            fprintf(stderr, "[LEapsInjector] %d process detach fail!!\n", pid);    
        }else fprintf(stdout, "[LEapsInjector] Restart [%d] process \n", pid);    
    }
    return 0;
}


unsigned long set_pointed_value(const pid_t pid, const unsigned long long addr, unsigned long long data){
    return ptrace(PTRACE_POKETEXT, pid, addr, data);
}
unsigned long get_pointed_value(const pid_t pid, const unsigned long long addr){
    return ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
}
int read_addr_into_buff(const pid_t pid, const unsigned long long addr, char* buff, unsigned int buff_size){
    unsigned int bytes_read = 0;
    long * read_addr = (long *) addr;
    long * copy_addr = (long *) buff;
    unsigned long ret;
    memset(buff, '\0', buff_size);
    
    do{ 
        ret = ptrace(PTRACE_PEEKTEXT, pid, (read_addr++), NULL);
        *(copy_addr++) = ret;
        bytes_read += sizeof(long);
    }while(ret && bytes_read < (buff_size - sizeof(long)));
    return bytes_read;
}
int write_text_to_addr(const pid_t pid, const unsigned long long addr, const char* buff){
    unsigned int bytes_read = 0;
    long * read_addr = (long *) buff;
    long * target_addr = (long *) addr;
    unsigned long ret;
    int bytes_lengnth = strlen(buff) + 1;
    
    do{ 
        if ((*read_addr) == 0){
            ret = ptrace(PTRACE_POKETEXT, pid, (target_addr++), *read_addr++);
            break;
        }
        ret = ptrace(PTRACE_POKETEXT, pid, (target_addr++), *read_addr++);
    }while(!ret);
    return bytes_read;
}

int get_pid_by_cmdline(const char* process_name){
    char fname[64];
    char status[64];

    int i, pid;
    FILE *fp = NULL;

    pid = -1;
    for (int i = 0; i < MAX_PROC_PID; i++){
        snprintf(fname, sizeof(fname), "/proc/%d/cmdline", i);
        if((fp=fopen(fname, "r")) == NULL) continue;
        if(fgets(status, sizeof(status), fp) != NULL){
            if(strstr(status, process_name) != NULL){
                pid = i;
                fclose(fp);
                return pid;
            }
        }
        fclose(fp);
    }
    return -1;
}

long internal_ptrace(int req, pid_t pid, void* addr, void* data){
    int ret, stat;
    errno = 0;
    while(1){
        stat = 0;
        ret = waitpid(pid, &stat, WNOHANG);
        if((ret == pid && WIFEXITED(stat)) || (WIFSTOPPED(stat) && !WSTOPSIG(stat))){
            fprintf(stderr, "[LEapsInjector] Killed Process: %d\n", pid);
            return -1;
        }
        if((ret = ptrace(req, pid, addr, data)) == -1){
            switch (req)
            {
            case PTRACE_DETACH:
            case PTRACE_SYSCALL:
            case PTRACE_KILL:
                return 0;
            default:
                break;
            }
        }else{
            break;
        }
    }
    return ret;
}
void sigint_fn(int signo){
    fprintf(stdout, "[LEapsInjector] Received Ctrl+C Signal. \n");
    if(init_pid != 0){
        if(PTRACE(PTRACE_DETACH, init_pid, (void*)1, 0) < 0){
            fprintf(stderr, "[LEapsInjector] PTRACE_DETACH error \n");
        }
    }
    exit(0);
}


int injectionEnvironment(int pid){
    struct user_regs_struct regs;
    int entry_flag = 1;
    char buffer[MAX_BUFFER_LEN];
    unsigned long env;
    unsigned long last_buffer_ptr;

    fprintf(stdout, "[LEapsInjector] start injection... [%d]\n", pid);    
    
    if(PTRACE(PTRACE_ATTACH, pid, (void*)1, 0) < 0){
        fprintf(stderr, "[LEapsInjector] PTRACE_ATTACH error \n");
        return -1;
    }
    fprintf(stdout, "[LEapsInjector] injection start\n");    

    while(1){
        if(PTRACE(PTRACE_GETREGS, pid, 0, &regs) < 0){
            fprintf(stderr, "[LEapsInjector] PTRACE_GETREGS error \n");
            goto fail;
        }
//        fprintf(stdout, "[%lu]", regs.orig_rax);        
        fprintf(stdout, "[%lu]", regs.orig_rax);
        switch (regs.orig_rax)
        {
        // case SYS_read:
        //     if (!entry_flag)
        //     {
        //         last_buffer_ptr = regs.rsi;
        //         read_addr_into_buff(pid, regs.rsi, buffer, MAX_BUFFER_LEN);
        //         fprintf(stdout, "READ [%lu]: %s\n", regs.rsi, buffer);
        //     }
        //     entry_flag = !entry_flag;
        //     break;
            
        case SYS_write:
            if (entry_flag)
            {
                read_addr_into_buff(pid, regs.rsi, buffer, MAX_BUFFER_LEN);
                fprintf(stdout, "WRITE: %s\n", buffer);
            }
            entry_flag = !entry_flag;
            break;
        case SYS_execve:
            if(entry_flag){
                fprintf(stdout, "[LEapsInjector] execve detect param:\n");
                read_addr_into_buff(pid, regs.rdi, buffer, MAX_BUFFER_LEN);
                fprintf(stdout, "filename: %s\n", buffer);

                const char ** envs = (const char **)regs.rdx;
                do{
                    if((env = get_pointed_value(pid, (unsigned long long)envs)) < 0){
                        fprintf(stdout, "[LEapsInjector] fail PTRACE_PEAKTEXT:\n");
                        goto fail;
                    }
                    if(env == 0) break;
                    read_addr_into_buff(pid, env, buffer, MAX_BUFFER_LEN);
                    printf("[%lu]>> %s\n", env, buffer);
                    envs++;
                }while(1);

                memset(buffer, 0, sizeof(buffer));
                strcpy(buffer, EXTRA_ENVIRONMENT);
                write_text_to_addr(pid, last_buffer_ptr, buffer);
                fprintf(stdout, "[LEapsInjector] inject environment : %s\n", buffer);
                // read_addr_into_buff(pid, last_buffer_ptr, buffer, MAX_BUFFER_LEN);
                // fprintf(stdout, "last buffer item: %s\n", buffer);

                if(set_pointed_value(pid, (unsigned long long)envs++, last_buffer_ptr) !=0){
                    fprintf(stdout, "[LEapsInjector] set pointed value(POKETEXT) fail : %lu\n", envs);
                    goto fail;
                }
                if(set_pointed_value(pid, (unsigned long long)envs, 0) !=0){
                    fprintf(stdout, "[LEapsInjector] set pointed value(POKETEXT) fail : %lu\n", envs);
                    goto fail;
                }
                // if(PTRACE(PTRACE_DETACH, pid, (void*)1, 0) < 0){
                //    fprintf(stderr, "[LEapsInjector] PTRACE_DETACH error \n");
                // }
                return 0;
            }
            entry_flag = !entry_flag;
            break;
        default:
            entry_flag = 1;
            break;
        }
        if(PTRACE(PTRACE_SYSCALL, pid, (void*)1, 0) < 0){
            fprintf(stderr, "[LEapsInjector] PTRACE SYSCALL_ERROR\n");    
            goto fail;
        }
    }

fail:
    return 0;
}

int getNewZygotePID(){
//    int zygote_path_check = 0;

    char buffer[MAX_BUFFER_LEN];
    int i, ret = -1;
    int zygote_pid = 0;
    int status;
    int entry_flag = 1;
    int find_zygote = 0;
    struct user_regs_struct regs;

    fprintf(stdout, "[LEapsInjector] get the current zygote pid...\n");    
    if((zygote_pid = get_pid_by_cmdline("zygote64")) < 0){
        fprintf(stderr, "[LEapsInjector] fail fetching current zygote pid.\n");    
        return -1;
    }
    fprintf(stdout, "[LEapsInjector] current zygote pid %d\n", zygote_pid);    
    
    if(PTRACE(PTRACE_ATTACH, init_pid, (void*)1, 0) < 0){
        fprintf(stderr, "[LEapsInjector] init process attach fail!!\n");    
        return -1;
    }

    kill(zygote_pid, SIGKILL);
    fprintf(stdout, "[LEapsInjector] send SIGKILL Signal\n");

        
    while(1){
        if(PTRACE(PTRACE_GETREGS, init_pid, (void*)1, &regs) < 0){
            fprintf(stderr, "[LEapsInjector] PTRACE_GETREGS error \n");
            ret = -1;
            goto fail;
        }
        switch (regs.orig_rax)
        {
        case SYS_newfstatat:
            if(entry_flag){
                read_addr_into_buff(init_pid, regs.rsi, buffer, MAX_BUFFER_LEN);
                fprintf(stdout, "[LEapsInjector] Check zygote process %s == %s ?\n", buffer, zygote64_identifier);
                if (strcmp(buffer, zygote64_identifier) == 0){
                    fprintf(stdout, "[LEapsInjector] find zygote signal %s %s\n", buffer, zygote64_identifier);
                    find_zygote = 1;
                }
            }
            entry_flag = !entry_flag;
            break;

        case SYS_clone:
            if(!entry_flag && find_zygote){
                fprintf(stdout, "[LEapsInjector] new zygote signal: %lu\n", regs.rax);
                ret = regs.rax;
                return ret;
            }
            entry_flag = !entry_flag;
            break;
        
        default:
            entry_flag = 1;
            break;
        }
        if(PTRACE(PTRACE_SYSCALL, init_pid, (void*)1, 0) < 0){
            fprintf(stderr, "[LEapsInjector] PTRACE SYSCALL_ERROR\n");    
            goto fail;
        }
    }
    
fail:
    if(PTRACE(PTRACE_DETACH, init_pid, 0, 0) < 0){
        fprintf(stderr, "[LEapsInjector] init process detach fail!!\n");    
    }
    return -1;
}
int main(void){
    int new_zygote_pid;
    signal(SIGINT, sigint_fn);
    fprintf(stdout, "[LEapsInjector] LEaps Shared library injector\n");
    new_zygote_pid = getNewZygotePID();
    injectionEnvironment(new_zygote_pid);

    finish(init_pid);
    finish(new_zygote_pid);

    return 0;
}
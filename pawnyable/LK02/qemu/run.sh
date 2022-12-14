#!/bin/sh
set -e
musl-gcc ./exp.c -static -I/home/biazo/Documents/pwnix/libpn -o exp
mv ./exp ./root

pn -r ./root
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr" \
    -no-reboot \
    -cpu kvm64,+smep \
    -monitor /dev/null \
    -initrd rootfs_updated.cpio \
    -net nic,model=virtio \
    -net user

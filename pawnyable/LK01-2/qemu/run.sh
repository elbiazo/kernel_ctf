#!/bin/sh
set -e
./compile.sh
mv ./exp ./root
pn -r ./root
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel bzImage \
    -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr=1" \
    -no-reboot \
    -cpu qemu64,+smap,+smep \
    -smp 1 \
    -monitor /dev/null \
    -initrd rootfs_updated.cpio \
    -net nic,model=virtio \
    -net user \
    -s

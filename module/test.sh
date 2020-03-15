#!/bin/bash
# Small script to test the write-interceptor module.
fs_maker="$1"

if [ "$fs_maker" = "" ]; then
    echo "Usage: ./test.sh mkfs.???"
    exit 1
fi

make

echo Installing kernel module...
sudo insmod write-interceptor.ko

echo Creating virtual mapping...
dd if=/dev/zero of=device_store bs=512 count=20000 status=none
loop_device_name=$(sudo losetup --find --show device_store)
echo -n > /tmp/output.txt
sudo dmsetup create wintercept-dev --table "0 20000 wintercept $loop_device_name /tmp/output.txt"

echo Giving ourselves read/write permission...
sudo chmod a+r /dev/mapper/wintercept-dev
sudo chmod a+w /dev/mapper/wintercept-dev

echo Running stress test...
./write-test.sh /dev/mapper/wintercept-dev $fs_maker

echo Removing the virtual mapping...
sudo dmsetup remove wintercept-dev
sudo losetup -d "$loop_device_name"

echo Removing kernel module...
sudo rmmod write_interceptor

echo You may erase the file device_store now.

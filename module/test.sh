#!/bin/bash
# Small script to test the write-interceptor module.

make

echo Installing kernel module...
sudo insmod write-interceptor.ko

echo Creating virtual mapping...
sudo dmsetup create wintercept-dev --table '0 20000 wintercept'

echo Giving ourselves read/write permission...
sudo chmod a+r /dev/mapper/wintercept-dev

echo Testing that the module returns only zeros...
cmp <(dd if=/dev/zero bs=512 count=20000 status=none) \
    <(dd if=/dev/mapper/wintercept-dev bs=512 count=20000 status=none)
if (($? == 0)); then
    echo The module correctly returns only zeros!
else
    echo Something went wrong...
fi

echo Removing the virtual mapping...
sudo dmsetup remove wintercept-dev

echo Removing kernel module...
sudo rmmod write_interceptor

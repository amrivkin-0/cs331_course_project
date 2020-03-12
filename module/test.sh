#!/bin/bash
# Small script to test the write-interceptor module.

make

echo Installing kernel module...
sudo insmod write-interceptor.ko

echo Creating virtual mapping...
dd if=/dev/zero of=device_store bs=512 count=20000 status=none
loop_device_name=$(sudo losetup --find --show device_store)
sudo dmsetup create wintercept-dev --table "0 20000 wintercept $loop_device_name"

echo Giving ourselves read/write permission...
sudo chmod a+r /dev/mapper/wintercept-dev
sudo chmod a+w /dev/mapper/wintercept-dev

echo Testing that the module returns only zeros...
cmp <(dd if=/dev/zero bs=512 count=20000 status=none) \
    <(dd if=/dev/mapper/wintercept-dev bs=512 count=20000 status=none)
if (($? == 0)); then
    echo The module correctly returns only zeros!
else
    echo Something went wrong...
fi

echo Writing some data...
echo SomeData > /dev/mapper/wintercept-dev
cmp <(dd if=/dev/mapper/wintercept-dev bs=1 count=8 status=none) <(echo -n SomeData)
if (($? == 0)); then
    echo The module correctly writes data!
else
    echo Something went wrong...
fi

echo Removing the virtual mapping...
sudo dmsetup remove wintercept-dev
sudo losetup -d "$loop_device_name"

echo Removing kernel module...
sudo rmmod write_interceptor

echo You may erase the file device_store now.

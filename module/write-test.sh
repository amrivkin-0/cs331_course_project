#!/bin/bash
device="$1"
fs_maker="$2"

RANDOM=123456

$fs_maker $device
mkdir -p device
sudo mount $device device
sudo chown "$(whoami):$(whoami)" device

for i in {0..9}; do
    mkdir device/$i
done

echo -n "WC after mkdir:        "
wc /tmp/output.txt -l

for i in {0..9}; do
    for j in {0..9}; do
        dd if=/dev/urandom of=device/$i/$j bs=512 count=32 status=none
    done
done

echo -n "WC after dd:           "
wc /tmp/output.txt -l

for count in {0..99}; do
    i=$((RANDOM%10))
    j=$((RANDOM%10))
    sector=$((RANDOM%1024))
    dd if=/dev/urandom of=device/$i/$j bs=16 count=1 seek=$sector conv=notrunc status=none
done

echo -n "WC after random dd:    "
wc /tmp/output.txt -l

sudo umount device
rmdir device

#!/bin/bash
all_fsmakers=(mkfs.ext4 mkfs.ntfs)
# The last one requires the package nilfs-tools

echo -n > log.txt

for i in {0..9}; do
    for fs_maker in "${all_fsmakers[@]}"; do
        ./test.sh "$fs_maker"
    done
done

#!/bin/sh

blk_size=262144
pad_end=4226953
img_end=4259840

[ -d build ] || mkdir build
[ -d out ] || mkdir out

rm -f ./build/*
rm -f ./out/*

mkimage -A mips -O linux -T kernel -C lzma -a 0X80002000 -e 0X80002000 -n SFP_7.5.3 -d source/kernel_g-010s-p.lzma build/uImage_g-010s-p

unsquashfs -exclude-file excludes -pf build/8311_g-010s-p.pseudo source/rootfs_g-010s-p.sqsh
mksquashfs - build/8311.squashfs -b 262144 -comp xz -pf build/8311_g-010s-p.pseudo -pf pseudofile

cat build/uImage_g-010s-p build/8311.squashfs > build/alcatel-g010sp_8311.img

img_size=`stat -c%s build/alcatel-g010sp_8311.img`

padding=$((pad_end-img_size)) bs=${blk_size} nblocks=$((padding/bs)) rest=$((padding%bs))
{
  dd if=/dev/zero bs=$bs count=$nblocks
  dd if=/dev/zero bs=$rest count=1
} 2>/dev/null >> build/alcatel-g010sp_8311.img

padding=$((img_end-pad_end)) bs=${blk_size} nblocks=$((padding/bs)) rest=$((padding%bs))
{
  dd if=/dev/zero bs=$bs count=$nblocks | tr "\000" "\377" >> build/alcatel-g010sp_8311.img
  dd if=/dev/zero bs=$rest count=1 | tr "\000" "\377" >> build/alcatel-g010sp_8311.img
} 2>/dev/null >> build/alcatel-g010sp_8311.img

cp build/alcatel-g010sp_8311.img out/alcatel-g010sp_8311.img

#!/bin/sh

FW_VARIANT="G-010S-P"

blk_size=262144
pad_end=4226953
img_end=4259840

sha256() {
	{ [ -n "$1" ] &&  sha256sum "$1" || sha256sum; } | awk '{print $1}'
}

[ -d build ] || mkdir build
[ -d out ] || mkdir out

rm -f ./build/*
rm -f ./out/*

GIT_HASH=$(git rev-parse --short HEAD)
GIT_DIFF="$(git diff HEAD)"
GIT_TAG=$(git tag --points-at HEAD | grep -P '^v\d+\.\d+\.\d+' | tr '-' '~' | sort -V -r | tr '~' '-' | head -n1)
GIT_EPOCH=$(git log -1 --format="%at")
GIT_EPOCH=${GIT_EPOCH:-$(date '+%s')}

FW_VER="${FW_VER:-${GIT_TAG:-""}}"
[ -n "$GIT_DIFF" ] && FW_SUFFIX="~$(echo "$GIT_DIFF" | sha256 | head -c 7)"
[ -n "$FW_VER" ] && FW_VERSION="${FW_VER}${FW_SUFFIX}" || { FW_VER="dev"; FW_VERSION="dev"; }

FW_REV="${FW_REV:-$GIT_HASH}"
FW_REVISION="$FW_REV$FW_SUFFIX"

FW_LONG_VERSION="${FW_VER}_${FW_VARIANT}_${FW_REV}${FW_SUFFIX}"

VERSION_FILE="./8311-mods/etc/8311_version"
cat > "$VERSION_FILE" <<8311_VER
FW_VER=$FW_VER
FW_VERSION=$FW_VERSION
FW_LONG_VERSION=$FW_LONG_VERSION
FW_REV=$FW_REV
FW_REVISION=$FW_REVISION
FW_VARIANT=$FW_VARIANT
FW_SUFFIX=$FW_SUFFIX
8311_VER

LUA8311="./8311-mods/usr/lib/lua/8311"
mkdir -pv "$LUA8311"
cat > "$LUA8311/version.lua" <<8311VER
module "8311.version"

variant = "${FW_VARIANT}"
version = "${FW_VERSION}"
revision = "${FW_REVISION}"
8311VER

mkimage -A mips -O linux -T kernel -C lzma -a 0X80002000 -e 0X80002000 -n SFP_7.5.3 -d source/kernel_g-010s-p.lzma build/uImage_g-010s-p

unsquashfs -exclude-file excludes -pf build/8311_g-010s-p.pseudo source/rootfs_g-010s-p.sqsh
mksquashfs - build/8311.squashfs -b 262144 -comp xz -pf build/8311_g-010s-p.pseudo -pf pseudofile

cat build/uImage_g-010s-p build/8311.squashfs > build/alcatel-g010sp_8311.img

img_size=$(stat -c%s build/alcatel-g010sp_8311.img)

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

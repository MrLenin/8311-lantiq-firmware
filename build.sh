#!/bin/sh

FW_VARIANT="G-010S-P"   # Image variant

BLOCK_SIZE=262144       # Image block size
ZZ_END=4226953          # End of '00' padding
FF_END=4259840          # End of 'FF' padding

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

mkimage -A mips -O linux -T kernel -C lzma -a 0X80002000 -e 0X80002000 -n SFP_7.5.3 -d ./source/kernel_g-010s-p.lzma ./build/uImage_g-010s-p
touch -d "@$GIT_EPOCH" ./source/kernel_g-010s-p.lzma ./build/uImage_g-010s-p

sed -r "s/@TIMESTAMP/$GIT_EPOCH/g" ./pseudofile >./build/pseudofile

# When passing unsquashfs '-pf -' WSL creates a pseudofile '-' which aside from creating other
# problems, defeats the entire point of piping...
case $(uname -r) in
  *WSL*)
    unsquashfs -exclude-file excludes -pf ./build/8311_g-010s-p.pseudo ./source/rootfs_g-010s-p.sqsh
    mksquashfs - ./build/8311.squashfs -b 262144 -comp xz -pf ./build/8311_g-010s-p.pseudo -pf ./build/pseudofile -mkfs-time "$GIT_EPOCH"
    ;;
  *)
    unsquashfs -exclude-file excludes -pf - ./source/rootfs_g-010s-p.sqsh | \
    mksquashfs - ./build/8311.squashfs -b 262144 -comp xz -pf - -pf ./build/pseudofile -mkfs-time "$GIT_EPOCH"
    ;;
esac

cat ./build/uImage_g-010s-p ./build/8311.squashfs >build/alcatel-g010sp_8311.img

IMG_SIZE=$(stat -c%s ./build/alcatel-g010sp_8311.img)

PADDING=$((ZZ_END-IMG_SIZE)) NUM_BLOCKS=$((PADDING/BLOCK_SIZE)) REST=$((PADDING%BLOCK_SIZE))
{
  dd if=/dev/zero bs=$BLOCK_SIZE count=$NUM_BLOCKS
  dd if=/dev/zero bs=$REST count=1
} 2>/dev/null >>build/alcatel-g010sp_8311.img

PADDING=$((FF_END-ZZ_END)) NUM_BLOCKS=$((PADDING/BLOCK_SIZE)) REST=$((PADDING%BLOCK_SIZE))
{
  dd if=/dev/zero bs=$BLOCK_SIZE count=$NUM_BLOCKS | tr "\000" "\377"
  dd if=/dev/zero bs=$REST count=1 | tr "\000" "\377"
} 2>/dev/null >>build/alcatel-g010sp_8311.img

touch -d "@$GIT_EPOCH" ./build/alcatel-g010sp_8311.img

mv ./build/alcatel-g010sp_8311.img ./out/alcatel-g010sp_8311.img

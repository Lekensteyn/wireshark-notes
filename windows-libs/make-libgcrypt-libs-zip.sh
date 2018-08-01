#!/bin/bash
# Create a libgcrypt-*-win??ws.zip file based on MingW packages.
#
# Copyright 2018, Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: (GPL-2.0-or-later or MIT)
set -eu

# Debian buster (already contains --disable-padlock-support --disable-asm)
# https://packages.debian.org/buster/libgpg-error-mingw-w64-dev
# https://packages.debian.org/buster/libgcrypt-mingw-w64-dev
# https://salsa.debian.org/debian/libgpg-error/blob/debian/1.32-1/debian/rules
# https://salsa.debian.org/gnutls-team/libgcrypt/blob/1.8.3-1/debian/rules
urls=(
http://ftp.nl.debian.org/debian/pool/main/libg/libgpg-error/libgpg-error-mingw-w64-dev_1.32-1_all.deb
http://ftp.nl.debian.org/debian/pool/main/libg/libgcrypt20/libgcrypt-mingw-w64-dev_1.8.3-1_all.deb
)
version=1.8.3

if [ -e usr ]; then
    echo "Remove usr/ before proceeding"
    exit 1
fi

# 1. Download .deb files if they are missing and verify integrity.
for url in "${urls[@]}"; do
    filename="${url##*/}"
    if [ ! -e "$filename" ]; then
        echo "Retrieving $url"
        curl -O "$url"
    fi
done
sha256sum --check <<SHA256
ff5eae9c905a7a9ca2cdd8ff8334e2a1f5846aa30c0e589b0ee74cd7560472ae  libgcrypt-mingw-w64-dev_1.8.3-1_all.deb
a4be1f60fa9035db79015ab2f4fa2c222233d19bbdd791ebdeaa3e5934254cae  libgpg-error-mingw-w64-dev_1.32-1_all.deb
SHA256

# 2. Unpack files.
for url in "${urls[@]}"; do
    filename="${url##*/}"
    bsdtar -xOf "$filename" data.tar.xz |
    bsdtar -xJvf- usr/x86_64-w64-mingw32 usr/i686-w64-mingw32
done

# 3. Patch header
echo "Patching ssize_t in gcrypt.h"
sed 's,typedef long ssize_t;,/*&*/,' -i usr/*/include/gcrypt.h

# 4. Relocate files and shrink their size.
# .def files are only needed to create .lib files. Do not bother.
# However, import libraries (.lib) files must be present.
for prefix in usr/*; do
    mv -v "$prefix/lib/libgcrypt.dll.a" "$prefix/bin/libgcrypt-20.lib"
    mv -v "$prefix/lib/libgpg-error.dll.a" "$prefix/bin/libgpg-error-0.lib"
    strip "$prefix/bin/"*.dll

    {
        echo "Downloaded from Debian Buster:"
        printf "%s\n" "${urls[@]}"
        printf "\nOther comments:\n"
        echo "- libgcrypt was compiled with --disable-asm and --disable-padlock-support flags"
        echo "- the ssize_t typedef was commented out in gcrypt.h; we define it elsewhere"
        echo "- lib/*.dll.a files were moved to bin/*.lib (including a version number based on the lib/*.dll file)"
        echo "- the .dll files were stripped (strip bin/*.dll)"
    } | sed 's/$/\r/' > "$prefix/README.Wireshark"
done

# 5. Create an archive
files=(
"bin/libgcrypt-20.dll"
"bin/libgcrypt-20.lib"
"bin/libgpg-error-0.dll"
"bin/libgpg-error-0.lib"
"include"
"README.Wireshark"
)
bsdtar -caf "libgcrypt-$version-win32ws.zip" -C usr/i686-w64-mingw32 "${files[@]}"
bsdtar -caf "libgcrypt-$version-win64ws.zip" -C usr/x86_64-w64-mingw32 "${files[@]}"

ls -l "libgcrypt-$version-win32ws.zip" "libgcrypt-$version-win64ws.zip"

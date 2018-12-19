#!/bin/bash
# Create a gnutls-*-win??ws.zip file based on MingW packages.
#
# Copyright 2018, Peter Wu <peter@lekensteyn.nl>
#
# SPDX-License-Identifier: (GPL-2.0-or-later or MIT)
set -eu
shopt -s extglob
umask 22

# Packaging sources and information:
# https://src.fedoraproject.org/rpms/mingw-gnutls/blob/f29/f/mingw-gnutls.spec
# https://apps.fedoraproject.org/packages/mingw64-gnutls
#
# parse-fedorarepo.py --ignore binutils --ignore cpp --ignore headers --ignore gcc-c++ --ignore crt --ignore pkg-config --release 29 mingw64-gnutls mingw32-gnutls --downloadUsing cached file repomd.xml
#
# Dependency tree:
# + mingw64-gnutls                                                 3.6.3-1.fc29.noarch
#   + mingw64-gcc (mingw64(libgcc_s_seh-1.dll))                    8.2.0-3.fc29.x86_64
#     + mingw64-winpthreads (mingw64(libwinpthread-1.dll))
#   + mingw64-gmp (mingw64(libgmp-10.dll))                         6.1.2-4.fc29.noarch
#     + mingw64-gcc (mingw64(libgcc_s_seh-1.dll))
#   + mingw64-nettle (mingw64(libhogweed-4.dll))                   3.4-2.fc29.noarch
#     + mingw64-gmp (mingw64(libgmp-10.dll))
#   + mingw64-nettle (mingw64(libnettle-6.dll))
#   + mingw64-p11-kit (mingw64(libp11-kit-0.dll))                  0.23.7-5.fc29.noarch
#     + mingw64-libffi (mingw64(libffi-6.dll))                     3.1-4.fc29.noarch
#     + mingw64-libtasn1 (mingw64(libtasn1-6.dll))
#   + mingw64-libtasn1 (mingw64(libtasn1-6.dll))                   4.13-3.fc29.noarch
#   + mingw64-winpthreads (mingw64(libwinpthread-1.dll))           5.0.4-2.fc29.noarch
#   + mingw64-libtasn1
# + mingw32-gnutls                                                 3.6.3-1.fc29.noarch
#   + mingw32-gcc (mingw32(libgcc_s_sjlj-1.dll))                   8.2.0-3.fc29.x86_64
#     + mingw32-winpthreads (mingw32(libwinpthread-1.dll))
#   + mingw32-gmp (mingw32(libgmp-10.dll))                         6.1.2-4.fc29.noarch
#     + mingw32-gcc (mingw32(libgcc_s_sjlj-1.dll))
#   + mingw32-nettle (mingw32(libhogweed-4.dll))                   3.4-2.fc29.noarch
#     + mingw32-gcc (mingw32(libgcc_s_sjlj-1.dll))
#     + mingw32-gmp (mingw32(libgmp-10.dll))
#   + mingw32-nettle (mingw32(libnettle-6.dll))
#   + mingw32-p11-kit (mingw32(libp11-kit-0.dll))                  0.23.7-5.fc29.noarch
#     + mingw32-libffi (mingw32(libffi-6.dll))                     3.1-4.fc29.noarch
#     + mingw32-gcc (mingw32(libgcc_s_sjlj-1.dll))
#     + mingw32-libtasn1 (mingw32(libtasn1-6.dll))
#   + mingw32-libtasn1 (mingw32(libtasn1-6.dll))                   4.13-3.fc29.noarch
#     + mingw32-gcc (mingw32(libgcc_s_sjlj-1.dll))
#   + mingw32-winpthreads (mingw32(libwinpthread-1.dll))           5.0.4-2.fc29.noarch
#   + mingw32-libtasn1
#
urls=(
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-gnutls-3.6.3-1.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-gcc-8.2.0-3.fc29.x86_64.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-gmp-6.1.2-4.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-nettle-3.4-2.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-p11-kit-0.23.7-5.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-libffi-3.1-4.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-libtasn1-4.13-3.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw64-winpthreads-5.0.4-2.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-gnutls-3.6.3-1.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-gcc-8.2.0-3.fc29.x86_64.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-gmp-6.1.2-4.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-nettle-3.4-2.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-p11-kit-0.23.7-5.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-libffi-3.1-4.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-libtasn1-4.13-3.fc29.noarch.rpm
https://mirror.nl.leaseweb.net/fedora/linux/releases/29/Everything/x86_64/os/Packages/m/mingw32-winpthreads-5.0.4-2.fc29.noarch.rpm
)
version=3.6.3-1

if [ -e usr ]; then
    echo "Remove usr/ before proceeding"
    exit 1
fi
for prog in curl objdump llvm-dlltool; do
    if ! type "$prog" &>/dev/null; then
        echo "Missing program: $prog"
        exit 1
    fi
done

# 1. Download .deb files if they are missing and verify integrity.
for url in "${urls[@]}"; do
    filename="${url##*/}"
    if [ ! -e "$filename" ]; then
        echo "Retrieving $url"
        curl -O "$url"
    fi
done
sha256sum --check <<SHA256
e61e22296b0365334dc60aa67986b845bba5208f1d562093cb53588f1113ed17  mingw64-gnutls-3.6.3-1.fc29.noarch.rpm
099d43f881e6c7182f20b743d54d0ef96590e6cadad8d37853a5accf9f6898fa  mingw64-gcc-8.2.0-3.fc29.x86_64.rpm
d0a60418a94ce429f2cdb919cc2730ac123be2259481afc2b857349693c2ad92  mingw64-gmp-6.1.2-4.fc29.noarch.rpm
48d3811ec95f44825539e4ef7c1290e74c05d1eabbc3fd66e7f60c1f3480a430  mingw64-nettle-3.4-2.fc29.noarch.rpm
5a11ed1bff0b50a0c97a8a084fe46975307f420ecf800eca42fd572a3fcf0f01  mingw64-p11-kit-0.23.7-5.fc29.noarch.rpm
bd97d7e514d7f4265f24411cca247b1f1666ef3056a5b9ba0017aeb9d2bb31f0  mingw64-libffi-3.1-4.fc29.noarch.rpm
6f64aa4dcb2eefed7017396ab4caf3ae22cb06b545b2d33891922226b1d9b228  mingw64-libtasn1-4.13-3.fc29.noarch.rpm
6044fb0fdd621ed3dc36556ac100f1e74285c5c0ffcf063c99eaa32f37e7e48e  mingw64-winpthreads-5.0.4-2.fc29.noarch.rpm
80a931b1e629f04fad3407f2f7cf9b7c680f79b4a036b9bee49f127f1f036f5a  mingw32-gnutls-3.6.3-1.fc29.noarch.rpm
160550a934b2728c284cb1a91d5c9866016231d3818cccae1c7eea3aac5d5198  mingw32-gcc-8.2.0-3.fc29.x86_64.rpm
b30b64b10faa3d9e910bf6058f7cf60d3fc7c6deca0cafbf60ba4232ba91a983  mingw32-gmp-6.1.2-4.fc29.noarch.rpm
973803a6583f960cb1ccba08c1f090de94d11ec789cdcb4fba9966c2f4c967e0  mingw32-nettle-3.4-2.fc29.noarch.rpm
f9b389aee9c28fdd43d5185055bbf096094e3c99710c7db2f92052796ce8aa8a  mingw32-p11-kit-0.23.7-5.fc29.noarch.rpm
9005175c35435d11b13ea99e76b68244ac578104ce10e79c26e7138c4372dd09  mingw32-libffi-3.1-4.fc29.noarch.rpm
6607f7103d3ac9ab7bf969366982a9e8ff2af531222edad766d7db4f18762222  mingw32-libtasn1-4.13-3.fc29.noarch.rpm
656246cd562363831ca447bb8fbf5f0b775be3d1a62146f289bb62cbd51ac6ae  mingw32-winpthreads-5.0.4-2.fc29.noarch.rpm
SHA256

# 2. Unpack files.
for url in "${urls[@]}"; do
    filename="${url##*/}"
    bsdtar -xf "$filename"
done

# 3. Patching
# (nothing to do)

# Given libxyz-1.dll, create import library libxyz-1.lib
make_implib() {
    local machine=$1 dll="$2" dllname deffile libfile

    dllname="${dll##*/}"
    deffile="${dll%.dll}.def"
    libfile="${dll%.dll}.lib"

    # Extract exports from the .edata section, writing results to the .def file.
    LC_ALL=C objdump -p "$dll" | awk -vdllname="$dllname" '
    /^\[Ordinal\/Name Pointer\] Table$/ {
        print "LIBRARY " dllname
        print "EXPORTS"
        p = 1; next
    }
    p && /^\t\[ *[0-9]+\] [a-zA-Z0-9_]+$/ {
        gsub("\\[|\\]", "");
        print "    " $2 " @" $1;
        ++p; next
    }
    p > 1 && /^$/ { exit }
    p { print "; unexpected objdump output:", $0; exit 1 }
    END { if (p < 2) { print "; cannot find export data section"; exit 1 } }
    ' > "$deffile"

    # Create .lib suitable for MSVC. Cannot use binutils dlltool as that creates
    # an import library (like the one found in lib/*.dll.a) that results in
    # broken executables. For example, assume executable foo.exe that uses fnA
    # (from liba.dll) and fnB (from libb.dll). Using link.exe (14.00.24215.1)
    # with these broken .lib files results in an import table that lists both
    # fnA and fnB under both liba.dll and libb.dll. Use of llvm-dlltool creates
    # the correct archive that uses Import Headers (like official MS tools).
    llvm-dlltool -m "$machine" -d "$deffile" -l "$libfile"
    rm -f "$deffile"
}

# 4. Install files, shrink their size and create a .zip.
# .def files are only needed to create .lib files. Do not bother.
# However, import libraries (.lib) files must be present.
for prefix in usr/*; do
    case $prefix in
    usr/i686-w64-mingw32)
        machine=i386
        destdir=gnutls-$version-win32ws
        ;;
    usr/x86_64-w64-mingw32)
        machine=i386:x86-64
        destdir=gnutls-$version-win64ws
        ;;
    *) continue ;;
    esac
    rm -rf "$destdir" "$destdir.zip"

    mkdir -m755 "$destdir" "$destdir/bin"
    cp -va "$prefix/sys-root/mingw/include" "$destdir/"
    # Optional, but perhaps useful for debugging.
    cp -va "$prefix/sys-root/mingw/bin/"*.exe "$destdir/bin/"
    cp -va "$prefix/sys-root/mingw/bin/"*.dll "$destdir/bin/"
    for dllpath in "$destdir/bin/"*-*.dll; do
        make_implib "$machine" "$dllpath"
    done
    # Saves only 500K (7%), prefer unmodified files.
    #strip "$destdir/bin/"*.dll

    {
        echo "Downloaded from Fedora:"
        printf "%s\n" "${urls[@]}"
        printf "\nOther comments:\n"
        echo "- the .lib files were generated using llvm-dlltool based on .def files extracted from objdump -p foo.dll"
        #echo "- the .dll files were stripped (strip bin/*.dll)"
    } | sed 's/$/\r/' > "$destdir/README.Wireshark"

    # Create zip, but without extra info such as timestamp and uid/gid (-X)
    zip -Xr "$destdir.zip" "$destdir"
done

ls -l "gnutls-$version-win32ws.zip" "gnutls-$version-win64ws.zip"

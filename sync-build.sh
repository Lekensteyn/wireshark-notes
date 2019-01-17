#!/bin/bash
# Detect a local change, sync to build machine and retrieve result when done. A
# notification is also send when the build is complete.
#
# Author: Peter Wu <peter@lekensteyn.nl>
#
# Recommendations:
# - ssh-agent (add keys before with ssh-add)
# - 2 GiB remote storage (builddir is 900 MiB, git tree is 486 MiB)
# - Gigabit link between working machine and build machine
# - Matching local + remote OS environments to avoid library mismatches.
#   In my case I run schroot to enter a chroot with matching libs (see
#   $remotecmd below).
# - libnotify for notifications when ready.
#
# Usage:
# $0 [buildhost] [cmake options --] [ninja options]
# - buildhost defaults to wireshark-builder (you can use user@host)
# - Optional env vars:
#   * CC, CXX, CFLAGS, CXXFLAGS - C/C++ compiler binary/flags
#   * CXXFLAGS  - C++ compiler flags (defaults to CFLAGS)
#   * EXTRA_CFLAGS - Appended to CFLAGS
#   * NOCOPY=1  - do not sync the generated binaries back
#   * B32=1     - build 32-bit (using /usr/lib32)
#   * force_cmake - Set to non-empty to run cmake before make.
#   * NOTRIGGER=1 - Do not immediately start building on execution
#   * BUILDDIR  - absolute path on remote and local side for built objects.

# LOCAL source dir (on non-volatile storage for reliability)
localsrcdir=$HOME/projects/wireshark/

# REMOTE
# REMOTE host, is a ssh alias that can be defined in ~/.ssh/config, e.g.:
# Host wireshark-builder
#    User foo
#    Hostname 10.42.0.1
# use 'localhost' for local builds without using rsync/ssh
remotehost=${1:-wireshark-builder}
# Remote source dir, it can be volatile (tmpfs) since it is just a copy. On the
# local side, it is recommended to create a symlink to the localsrcdir for
# debugging purposes
remotesrcdir=/tmp/wireshark/
# Remote directory to generate objects, it must also be accessible locally for
# easier debugging (can move it as needed).
builddir=${BUILDDIR:-/tmp/wsbuild/}

CC=${CC:-cc}
CXX=${CXX:-c++}
# For clang, `-O1` (or `-g`?) seems necessary to get something other than
# "<optimized out>".
# -O1 -g -gdwarf-4 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
_default_flags=-fdiagnostics-color
if $CC --version | grep -qE 'clang version ([89]|[1-9][0-9])'; then
    # Require Clang and at least LLD 8.0 to avoid broken binaries and crashes.
    # https://bugs.llvm.org/show_bug.cgi?id=37303
    _default_flags+=\ -fuse-ld=lld
else
    _default_flags+=\ -fuse-ld=gold
fi
# -fdebug-prefix-map is supported in GCC since 2007 (?), but only in Clang 3.8
# In GDB, use "dir /tmp/wireshark" to add the source directory anyway.
# -fmacro-prefix-map and -ffile-prefix-map were added in GCC 8. Hopefully it
# becomes available in Clang 8, see https://bugs.llvm.org/show_bug.cgi?id=38135
_default_flags+=" -fdebug-prefix-map=$builddir="
_default_flags+=" -fdebug-prefix-map=$remotesrcdir="
CFLAGS="${CFLAGS-$_default_flags -fno-common}${EXTRA_CFLAGS:+ $EXTRA_CFLAGS}"
# Default to use the same CXXFLAGS as CFLAGS (common case)
CXXFLAGS="${CXXFLAGS-$CFLAGS}"

LIBDIR=/usr/lib
# Run with `B32=1 ./sync-build.sh` to build for multilib
if [[ ${B32:-} ]]; then
    LIBDIR=/usr/lib32
    CFLAGS="$CFLAGS -m32"
    CXXFLAGS="$CXXFLAGS -m32"
fi

# Override RPATH to allow for relocatable executables.
# As extcap/androiddump is located in a subdir, add a special case for that.
# This is NOT suitable (safe) for release! If you ever move the "run" directory,
# be sure not to have an untrusted "extcap" directory next to it.
# This should no longer be necessary once CMAKE_BUILD_RPATH_USE_ORIGIN is set.
# See https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=15163#c4
RPATH='$ORIGIN:$ORIGIN/../extcap/..'

# Set envvar force_cmake=1 to call cmake before every build
if [ -n "${force_cmake:-}" ]; then
    force_cmake=true
else
    force_cmake=false
fi

# Drop $remotehost
shift

cmake_options=()
ninja_options=()
while [ $# -gt 0 ]; do
    if [[ $1 == -- ]]; then
        cmake_options=("${ninja_options[@]}")
        shift
        ninja_options=("$@")
        break
    fi
    ninja_options+=("$1")
    shift
done

# PATH is needed for /usr/bin/core_perl/pod2man (PCAP)
# ENABLE_QT5=1: install qt5-tools qt5-multimedia on Arch Linux
# BUILD_sshdump=1: install libssh on Arch Linux
# 32-bit libs on Arch: lib32-libcap lib32-gnutls lib32-krb5 lib32-libnl
remotecmd="mysh() {
    if [ -e /etc/arch-release ]; then
        # In Arch root, so do a build
        sh \"\$@\"
    else
        # Not in Arch root, so enter chroot to ensure matching libs
        schroot -c chroot:arch -- sh \"\$@\";
    fi
}; mysh -c '
PATH=\$PATH:/usr/bin/core_perl;
if $force_cmake || [ ! -e $builddir/CMakeCache.txt ]; then
    mkdir -p $builddir && cd $builddir &&
    set -x &&
    time \
    CC=$CC CXX=$CXX \
    PKG_CONFIG_LIBDIR=$LIBDIR/pkgconfig:/usr/share/pkgconfig \
    cmake \
        -GNinja \
        -DCMAKE_INSTALL_PREFIX=/tmp/wsroot \
        -DCMAKE_BUILD_WITH_INSTALL_RPATH=1 \
        -DCMAKE_INSTALL_RPATH=$(printf %q "$RPATH") \
        -DENABLE_SMI=0 \
        -DCMAKE_BUILD_TYPE=Debug \
        -DDISABLE_WERROR=1 \
        -DENABLE_ASAN=1 \
        -DENABLE_UBSAN=1 \
        $remotesrcdir \
        -DCMAKE_LIBRARY_PATH=$LIBDIR \
        -DCMAKE_C_FLAGS=$(printf %q "$CFLAGS") \
        -DCMAKE_CXX_FLAGS=$(printf %q "$CXXFLAGS") \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
        $(printf ' %q' "${cmake_options[@]}")
fi &&
time \
ASAN_OPTIONS=detect_leaks=0 \
ninja -C $builddir $(printf ' %q' "${ninja_options[@]}")
'"


# Touch this file to trigger a build.
sync=$(mktemp --tmpdir 'sync-build-XXXXXXXX')
monpid=
cleanup() {
    rm -f "$sync"
    [ -z "$monpid" ] || kill $monpid
}
trap cleanup EXIT

round=0
monitor_changes() {
    # Wait for changes, but ignore .git/, vim swap files, tests, the
    # pytest_cache and Python 3 cache directory.
    # NOTE: you cannot add multiple --exclude options, they must be combined
    inotifywait -r -m -e close_write \
        --exclude='/(\.[^/]+)?\.swp?.$|~$|\/(\.git|test|\.pytest_cache|__pycache__)/' \
        "$localsrcdir/" |
    while read x; do
        printf '\e[36m%s\e[m\n' "Trigger $((++round)): $x" >&2
        touch "$sync"
    done
}


### MAIN ###

# For gdb
if [ ! -e "${remotesrcdir%%/}" ]; then
    ln -sv "$localsrcdir" "${remotesrcdir%%/}"
fi
# In case /tmp/wireshark/ exists but is different.
localsrcdir=$remotesrcdir

monitor_changes & monpid=$!

if [ -z "${NOTRIGGER:-}" ]; then
    sleep .5 && touch "$sync" &
fi

echo Waiting...
while inotifywait -qq -e close_write "$sync"; do
    echo Woke up...
    # Wait for a second in case I save something and want to do a ninja edit.
    sleep 1

    if [[ $remotehost == localhost ]]; then
        # Do not bother copying files for local builds
        sh -c "$remotecmd"
    else
        # IMPORTANT: do not sync top-level config.h or it will break OOT builds
        rsync -avi --delete --exclude='.*.sw?' \
            -z \
            --exclude=/config.h \
            --exclude=/compile_commands.json \
            --exclude=\*.tar\* \
            "$localsrcdir/" "$remotehost:$remotesrcdir/" &&
        ssh -t "$remotehost" "$remotecmd"
    fi
    retval=$?
    if [ $retval -ne 0 ]; then
        notify-send -- "$(tty) - $(date -R)" "Build broke with $retval"
        sleep 2
    else
        mkdir -p "$builddir"
        [[ $remotehost == localhost ]] || [ -n "${NOCOPY:-}" ] ||
        rsync -avi --delete \
            -z \
            --exclude='.*.sw?' \
            --exclude='*.a' \
            "$remotehost:$builddir/"{compile_commands.json,config.h} \
            "$remotehost:$builddir/run" \
            "$builddir/"
        notify-send -- "$(tty) - $(date -R)" "READY"
    fi
    echo Another satisfied customer. NEXT
done

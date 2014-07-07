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

# LOCAL source dir (on non-volatile storage for reliability)
localsrcdir=$HOME/projects/wireshark/

# REMOTE
# REMOTE host, is a ssh alias that can be defined in ~/.ssh/config, e.g.:
# Host wireshark-builder
#    User foo
#    Hostname 10.42.0.1
remotehost=wireshark-builder
# Remote source dir, it can be volatile (tmpfs) since it is just a copy. On the
# local side, it is recommended to create a symlink to the localsrcdir for
# debugging purposes
remotesrcdir=/tmp/wireshark/
# Remote directory to generate objects, it must also be accessible locally for
# easier debugging (rpath)
builddir=/tmp/wsbuild/

# LOCAL & REMOTE program dir (Available since 1.11.x and 1.12.0)
rundir="$builddir/run/"

# PATH is needed for /usr/bin/core_perl/pod2man (PCAP)
remotecmd="schroot -c chroot:arch -- sh -c '
PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/bin/core_perl;
if [ ! -d $builddir ]; then
    mkdir $builddir && cd $builddir &&
    time cmake \
        -DCMAKE_INSTALL_PREFIX=/tmp/wsroot \
        -DENABLE_GTK3=0 \
        -DENABLE_PORTAUDIO=0 \
        -DENABLE_QT5=0 \
        -DENABLE_GEOIP=0 \
        -DENABLE_KERBEROS=0 \
        -DENABLE_SMI=0 \
        -DCMAKE_BUILD_TYPE=Debug \
        $remotesrcdir \
        -DCMAKE_C_FLAGS=-fsanitize=address \
        -DCMAKE_CXX_FLAGS=-fsanitize=address \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=1
fi &&
time make -C $builddir -j16
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
    # Wait for changes, but ignore .git/ and vim swap files
    # NOTE: you cannot add multiple --exclude options, they must be combined
    inotifywait -r -m -e close_write \
        --exclude='/\.[^/]+\.swp?.$|~$|\/.git/' \
        "$localsrcdir/" |
    while read x; do
        printf '\e[36m%s\e[m\n' "Trigger $((++round)): $x" >&2
        touch "$sync"
    done
}


### MAIN ###

# For gdb
if [ ! -e "$remotesrcdir" ]; then
    ln -sv "$localsrcdir" "$remotesrcdir"
fi

monitor_changes & monpid=$!

echo Waiting...
while inotifywait -qq -e close_write "$sync"; do
    echo Woke up...
    # Wait for a second in case I save something and want to do a ninja edit.
    sleep 1

    rsync -av --delete --exclude='.*.sw?' \
        "$localsrcdir/" "$remotehost:$remotesrcdir/" &&
    ssh -t "$remotehost" "$remotecmd"
    retval=$?
    if [ $retval -ne 0 ]; then
        notify-send -- "$(tty) - $(date -R)" "Build broke with $retval"
        sleep 3
    else
        rsync -av --delete --exclude='.*.sw?' "$remotehost:$rundir" "$rundir"
        notify-send -- "$(tty) - $(date -R)" "READY"
    fi
    echo Another satisfied customer. NEXT
done

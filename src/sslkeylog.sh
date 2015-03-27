#!/bin/bash
# Invokes the given command, displaying the pre-master secrets to stderr
# (or to the file given by envvar SSLKEYLOGFILE).
#
# Example usage:
# SSLKEYLOGFILE=premaster.txt ./sslkeylog.sh curl https://lekensteyn.nl/

# Do not load the library into gdb or the shell launched by gdb. This prevent
# crashes when the library is built with -fsanitize=address and such.
gdb() {
    export -n LD_PRELOAD
    command gdb -q \
        -ex 'set startup-with-shell off' \
        -ex "set environment LD_PRELOAD=$LD_PRELOAD" \
        "$@"
}

LD_PRELOAD=$(readlink -f "${BASH_SOURCE[0]%/*}")/libsslkeylog.so
SSLKEYLOGFILE=${SSLKEYLOGFILE:-/dev/stderr}
export LD_PRELOAD SSLKEYLOGFILE

# Run the command (if not sourced)
[[ ${BASH_SOURCE[0]} != $0 ]] || \
"$@"

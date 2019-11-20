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

case "$OSTYPE" in
darwin*)
    # Unfortunately not all executables can be injected (e.g. /usr/bin/curl).
    # See also man dyld
    #
    #   "Note: If System Integrity Protection is enabled, these environment
    #    variables are ignored when executing binaries protected by System
    #    Integrity Protection."
    #
    # Note that DYLD_* env vars are *not* propagated though system binaries such
    # as bash. To set an environment variable, use 'env' as in:
    #
    #   ./sslkeylog.sh env DYLD_PRINT_OPTS=1 python3
    #
    # If the variable is picked up, it should show something like:
    #
    #   opt[0] = "python3"
    #
    # If not visible, then interception is not possible until SIP is disabled.

    export DYLD_INSERT_LIBRARIES=$(cd "${BASH_SOURCE[0]%/*}" && pwd)/libsslkeylog.dylib
    export DYLD_FORCE_FLAT_NAMESPACE=1
    # Expected output: dyld: loaded: <1A23FBC9-68C9-3808-88A5-C2D3A18C7DE1> .../wireshark-notes/src/libsslkeylog.dylib
    #export DYLD_PRINT_LIBRARIES=1
    # Expected output: dyld: lazy bind: openssl:0x105B21CE0 = libsslkeylog.dylib:_SSL_new, *0x105B21CE0 = 0x105B59660
    #export DYLD_PRINT_BINDINGS

    # Since DYLD is not propagated when using 'env', simulate it here.
    # This is safer than using 'eval'.
    if [[ ${BASH_SOURCE[0]} == $0 ]] && [[ "$1" == env ]]; then
        shift
        while [ $# -gt 0 ]; do
            case "$1" in
            *=*)
                export "$1"
                shift
                ;;
            *)
                break
            esac
        done
    fi
    ;;
*)
    export LD_PRELOAD=$(readlink -f "${BASH_SOURCE[0]%/*}")/libsslkeylog.so
    ;;
esac
export SSLKEYLOGFILE=${SSLKEYLOGFILE:-/dev/stderr}

# Run the command (if not sourced)
[[ ${BASH_SOURCE[0]} != $0 ]] || \
"$@"

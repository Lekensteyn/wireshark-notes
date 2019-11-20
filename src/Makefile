
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIBNAME := libsslkeylog.dylib
	# Assumes default Homebrew installation prefix.
	OPENSSL_PREFIX ?= /usr/local/opt/openssl@1.1
ifneq ($(OPENSSL_PREFIX),)
	CPPFLAGS ?= -I$(OPENSSL_PREFIX)/include
	# Link to library to avoid having to set LD_LIBRARY_PATH at runtime.
	LDFLAGS ?= -L$(OPENSSL_PREFIX)/lib -lssl
endif
else
	LIBNAME := libsslkeylog.so
endif

$(LIBNAME): sslkeylog.c
	$(CC) $(CPPFLAGS) $(CFLAGS) sslkeylog.c -shared -o $@ -fPIC -ldl $(LDFLAGS)

clean:
	$(RM) $(LIBNAME)


libsslkeylog.so: sslkeylog.c
	$(CC) $(CFLAGS) sslkeylog.c -shared -o $@ -fPIC -ldl

clean:
	$(RM) libsslkeylog.so

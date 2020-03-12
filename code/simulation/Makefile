CC=gcc
CFLAGS= -I. -lsodium -lssl -lcrypto -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include
DEPS = abstraction.h
OBJ = abstraction.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

abstraction: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
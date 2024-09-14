CC = gcc
CFLAGS = -fPIC -shared -Wall -O2 -std=gnu99
LIBNAME = libexecve_filter.so

all: $(LIBNAME)

$(LIBNAME): execve_filter.c
	$(CC) $(CFLAGS) -o $(LIBNAME) execve_filter.c -lpthread

clean:
	rm -f $(LIBNAME)


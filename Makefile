CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -g -fPIC
LDFLAGS=-g
LDLIBS=-lm

# List of executables to build
EXECUTABLES=cmdline_test fish

all: clean $(EXECUTABLES)

cmdline_test: cmdline_test.o libcmdline.so
	$(CC) $(LDFLAGS) $^ -o $@

fish: fish.o libcmdline.so
	$(CC) $(LDFLAGS) $^ -o $@

libcmdline.so: cmdline.o
	$(CC) -shared -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Dependencies
cmdline_test.o: cmdline_test.c cmdline.h
fish.o: fish.c cmdline.h
cmdline.o: cmdline.c cmdline.h

.PHONY: clean mrproper

clean:
	rm -f *.o
	rm -f libcmdline.so
	rm -f $(EXECUTABLES)

mrproper: clean
	# rm -f *~
	# For VIm temporary files

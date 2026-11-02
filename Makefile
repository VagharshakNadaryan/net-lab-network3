CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -fno-strict-aliasing

build/network3: src/network3.c
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $< -lnetfilter_queue -lcrypto

clean:
	rm -rf build

CC=gcc
CFLAGS=-Wall -Wextra
SRCDIR=src
BINDIR=bin

all: build

build:
	@mkdir -p $(BINDIR)
	$(CC) $(CFLAGS) -o $(BINDIR)/packet_sniffer $(SRCDIR)/packet_sniffer.c
	$(CC) $(CFLAGS) -o $(BINDIR)/packet_client $(SRCDIR)/packet_client.c
	@echo "Build complete!"

clean:
	rm -rf $(BINDIR)

server-setup:
	@./scripts/server_setup.sh

client-setup:
	@./scripts/client_setup.sh

.PHONY: all build clean server-setup client-setup
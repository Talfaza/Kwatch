CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	go generate ./...

build: generate
	go build -o kwatch .

run: build
	sudo ./kwatch
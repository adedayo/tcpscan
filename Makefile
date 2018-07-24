ifeq ($(OS),Windows_NT)
	BUILDFLAGS += ""
else 
	UNAME_S := $(shell uname -s)
	OUTFILE := "tcpscan-$(VERSION)-$(UNAME_S).tar.gz"
	ifeq ($(UNAME_S),Linux)
		BUILDFLAGS += -a -ldflags '-w -extldflags "-static -lpcap"'
	endif
	ifeq ($(UNAME_S),Darwin)
		BUILDFLAGS += -a
	endif
endif

all: tar

tar: build
	tar cvf $(OUTFILE) $(GOPATH)/bin/tcpscan
build:
	go build $(BUILDFLAGS) github.com/adedayo/tcpscan/cmd/tcpscan


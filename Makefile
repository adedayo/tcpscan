ifeq ($(OS),Windows_NT)
	BUILDFLAGS += ""
else 
	UNAME_S := $(shell uname -s)
	VERSION_TAG := $(shell git describe --abbrev=0 --tags)
	OUTFILE := "tcpscan_$(VERSION_TAG)_$(UNAME_S)_x86_64.tar.gz"
	ifeq ($(UNAME_S),Linux)
		BUILDFLAGS += -a -ldflags '-w -extldflags "-static"'
	endif
	ifeq ($(UNAME_S),Darwin)
		BUILDFLAGS += -a
	endif
endif

all: tar

tar: build
	echo $(VERSION_TAG) $(OUTFILE)
	tar cvf $(OUTFILE) tcpscan -C $(GOPATH)/bin
build:
ifeq ($(UNAME_S),Linux)
	sed -i "s/0.0.0/$(VERSION_TAG)/g" "cmd/tcpscan/tcpscan.go"
endif
	go build $(BUILDFLAGS) github.com/adedayo/tcpscan/cmd/tcpscan


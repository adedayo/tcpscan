ifeq ($(OS),Windows_NT)
	BUILDFLAGS += ""
else 
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		BUILDFLAGS += -a -ldflags '-w -extldflags "-static -lpcap"'
	endif
	ifeq ($(UNAME_S),Darwin)
		BUILDFLAGS += -a
	endif
		
endif
all:
	go build $(BUILDFLAGS) github.com/adedayo/tcpscan/cmd/tcpscan

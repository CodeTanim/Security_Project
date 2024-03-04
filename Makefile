SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
HEADERS := $(wildcard *.h)
TARGETS := kem-enc
TSOURCE := $(wildcard tests/*.c)
TESTS   := $(TSOURCE:.c=)

COMMON   := -O2 -Wall
# Include paths for GMP and OpenSSL headers
CFLAGS   := $(CFLAGS) $(COMMON) -I/opt/homebrew/include -I/opt/homebrew/opt/openssl@3/include
CC       := gcc
LDADD    := -lcrypto -lssl -lgmp
LD       := $(CC)
# Library paths for GMP and OpenSSL libraries
LDFLAGS  := -L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/lib
DEFS     :=
ifeq ($(shell uname),Linux)
DEFS += -DLINUX
endif

IMPL := ske.o rsa.o kem-enc.o
ifdef skel
IMPL := $(IMPL:.o=-skel.o)
endif

all : $(TARGETS)
.PHONY : all

# {{{ for debugging
debug : CFLAGS += -g -DDEBUG=1
debug : $(TARGETS) $(TESTS)
.PHONY : debug
# }}}

$(OBJECTS) : %.o : %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGETS) : $(IMPL) prf.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

tests : $(TESTS)
.PHONY : tests

$(TESTS) : % : %.o $(filter-out kem-enc.o,$(IMPL)) prf.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

.PHONY : clean
clean :
	rm -f $(OBJECTS) $(TARGETS) $(TESTS) $(TSOURCE:.c=.o)

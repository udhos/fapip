#
# $Id: Makefile,v 1.2 2009/05/26 21:53:11 evertonm Exp $
#

CC      = gcc
WARN    = -Wall -W -Werror
REENT   = -D_REENTRANT
DEBUG   = 
CFLAGS  = $(WARN) $(REENT) $(DEBUG) -g -ggdb
LDFLAGS +=

PLATFORM=$(shell uname)

ifeq ($(PLATFORM),SunOS)
SPARC64 = -m64 -mcpu=v9
LDFLAGS += $(SPARC64)
LDFLAGS += -lsocket -lnsl
endif

OBJ    = main.o

TARGET = fapip

.PHONY: default
default: $(TARGET)

.PHONY: clean
clean:
	rm -f *.o *~ $(TARGET)

.PHONY: build
build: clean default

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^

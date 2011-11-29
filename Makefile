CC=gcc
CFLAGS=-Wall -O3
LDFLAGS=-lpthread
ifeq ($(DEBUG),y)
  CFLAGS+=-g
  LDFLAGS+=-g
endif

all: tgen
tgen.o: 

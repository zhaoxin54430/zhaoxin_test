#all: clatdm

#clatdm: clatdm.c
#	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

#clean:
#	rm -f clatdm *.o

CC=gcc
WFLAGS=-Wall
CFLAGS=-O2
INCLUDES=-Iinclude

all: clatdm

OBJS = clatdm.o

%.o: %.c
	$(CC) $(WFLAGS) -c -o $@ $(INCLUDES) $(CFLAGS) $<

clatdm: $(OBJS)
	$(CC) -o $@ $(OBJS)

#clatdm: %.o
#	$(CC) -o $@ $<

clean:
	rm -f clatdm  *.o

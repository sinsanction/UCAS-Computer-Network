TARGET = mospfd

all: $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Wno-unused-variable -Wno-unused-function -Wno-address-of-packed-member -Iinclude
LDFLAGS = -L.

LIBS = -lpthread

HDRS = ./include/*.h

SRCS = arp.c arpcache.c device_internal.c icmp.c ip_base.c ip.c main.c mospf_database.c mospf_daemon.c mospf_proto.c rtable.c rtable_internal.c 
OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(LIBIP) $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS) 

clean:
	rm -f *.o $(TARGET)

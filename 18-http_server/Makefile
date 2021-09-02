CC = gcc
CFLAGS = -g -Wall -Wno-unused-variable -Wno-unused-function -Wno-address-of-packed-member -Iinclude
LIBS = -lpthread -ldl -lrt
HDRS = ./include/*.h

SRCS := $(wildcard $(SRC_DIR)*.c)
OBJS := $(SRCS:.c=.o)
TARGET := http_server

all : $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(OBJS) : %.o : %.c include/*.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean: 
	rm -rf $(SRC_DIR)*.o $(TARGET)

.PHONY:clean

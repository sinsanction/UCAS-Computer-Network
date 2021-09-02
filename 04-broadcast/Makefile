all: hub

hub: main.c broadcast.c device_internal.c
	gcc -Iinclude/ -Wall -g main.c broadcast.c device_internal.c -o hub

clean:
	@rm -f hub

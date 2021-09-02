#!/usr/bin/python2

import sys
import string
import socket
from time import sleep

data = string.digits + string.lowercase + string.uppercase

def server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    s.bind(('0.0.0.0', int(port)))
    s.listen(3)
    
    cs, addr = s.accept()
    print addr

    f = open('server-output.dat', 'wb')
    
    while True:
        data = cs.recv(20000)
        print len(data)
        f.write(data)
        #if data:
            #data = 'server echoes: recv ok'
            #cs.send(data)
        if len(data) == 0:
            break
    
    f.close()
    s.close()


def client(ip, port):
    s = socket.socket()
    s.connect((ip, int(port)))

    f = open('client-input.dat', 'r')
    file_str = f.read()
    length = len(file_str)
    i = 0

    while length > 0:
        send_len = min(length, 10000)
        s.send(file_str[i: i+send_len])
        sleep(0.1)
        #print s.recv(500)
        length -= send_len
        i += send_len
    
    sleep(0.2)
    f.close()
    s.close()

if __name__ == '__main__':
    if sys.argv[1] == 'server':
        server(sys.argv[2])
    elif sys.argv[1] == 'client':
        client(sys.argv[2], sys.argv[3])

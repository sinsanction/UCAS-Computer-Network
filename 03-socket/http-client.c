/* client application */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
 
int main(int argc, char *argv[])
{
    int sock;
    struct sockaddr_in server;
    char request[1000];
    char *server_reply;
    char ip[20];
    char file_path[20];
    int port;
    
    // check argument
    if (argc != 2) {
        printf("argument error");
		return -1;
    }
    // get ip and port
    char *input = argv[1];
    char *ip_begin = strstr(input, "http://");
    if(ip_begin == NULL)
        ip_begin = input;
    else
        ip_begin += 7;
    strcpy(ip, ip_begin);

    char *ip_end = ip;
    while(*ip_end != '/' && *ip_end != ':' && *ip_end != '\0'){
        ip_end++;
    }
    if(*ip_end == '\0'){
        port = 80;
        file_path[0] = '/';
        file_path[1] = '\0';
    }
    if(*ip_end == '/'){
        strcpy(file_path, ip_end);
        *ip_end = '\0';
        port = 80;
    }
    if(*ip_end == ':'){
        *ip_end = '\0';
        char *port_begin = ip_end + 1;
        port = 0;
        while (*port_begin != '\0') {
            if (*port_begin >= '0' && *port_begin <= '9') {
                port = port * 10 + (*port_begin - '0');
                port_begin++;
            }
            else{
                strcpy(file_path, port_begin);
                break;
            }
        }
    }
    printf("ip: %s port: %d\n", ip, port);
    fflush(stdout);

    // create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        printf("create socket failed");
		return -1;
    }
    printf("socket created\n");
    fflush(stdout);
     
    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
 
    // connect to server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("connect failed");
        return 1;
    }
     
    printf("connected\n");
    fflush(stdout);


    // send get request
    printf("send GET request: %s\n", input);
    sprintf(request, "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Close\r\n\r\n", file_path, ip, port);
    printf("%s", request);

    char file_name[20] = "client.";
    strcpy(&file_name[strlen(file_name)], file_path + 1);
    printf("file_name: %s\n", file_name);
    fflush(stdout);

    if (send(sock, request, strlen(request), 0) < 0) {
        printf("send failed\n");
        return 1;
    }
    
    // receive a reply from the server
    int len = 0, len_now = 0, size_now = 1;
	server_reply = malloc(4000 * sizeof(char));

    while ((len_now = recv(sock, server_reply + len, 4000, 0)) > 0) {
        len += len_now;
        if(size_now * 4000 - len < 4000){
            size_now++;
            server_reply = realloc(server_reply, size_now * 4000);
        }
    }
    if (len < 0) {
        printf("recv failed\n");
        return 1;
    }
	server_reply[len] = 0;
    
    // process response messages
    char *state_ok = strstr(server_reply, "200 OK");
    char *state_false = strstr(server_reply, "404 File Not Found");
    char *state_bad = strstr(server_reply, "400 Bad Request");
    printf("Server Reply: (%d)\n", len);
    if (state_ok) {
        char *header_end = strstr(server_reply, "\r\n\r\n");
        char file_name[20] = "client.";
        strcpy(&file_name[strlen(file_name)], file_path + 1);
        printf("%s\n", file_name);
        FILE *fp = fopen(file_name, "w+");
        if (header_end && fp) {
            int body = (header_end - server_reply) + 4;
            server_reply[body-1] = '\0';
            printf("%s", server_reply);
            fprintf(fp, "%s", &server_reply[body]);
            fflush(stdout);
            fclose(fp);
        }
        else{
            printf("%s", server_reply);
        }
    }
    else if (state_false) {
        printf("%s", server_reply);
        printf("404 File Not Found : The target file does not exist.\n");
    }
    else if (state_bad) {
        printf("%s", server_reply);
        printf("400 Bad Request : Request error.\n");
    }
    else {
        printf("%s", server_reply);
    }

    close(sock);
    return 0;
}

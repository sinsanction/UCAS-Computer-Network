#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

void handle_request(int cs){
    char response[2000];
    char request[2000];
    int request_len = 0;
    int i;

    // receive a message from client
    request_len = recv(cs, request, 2000, 0);
    if (request_len < 0) {
        printf("recv failed\n");
        return;
    }
    request[request_len] = '\0';

    printf("\nrequest: (%d)\n", request_len);
    printf("%s", request);
    fflush(stdout);
    char *req_get = strstr(request, "GET ");
    if (req_get) {
        // find target file path
        char *file_name, *file_name_end;
        file_name_end = file_name = req_get + 5;
        while (*file_name_end != ' ' && *file_name_end != '\0') {
            file_name_end++;
        }
        *file_name_end = '\0';

        printf("%s\n", file_name);
        fflush(stdout);

        // open target file
        FILE *fp = fopen(file_name, "r");
        if (fp) { // target file exist
            // read target file
            int file_size;
            fseek(fp, 0, SEEK_END);
            file_size = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            char *tmp = (char *)malloc(file_size * sizeof(char));
            memset(tmp, '\0', file_size * sizeof(char));
            fread(tmp, sizeof(char), file_size, fp);

            // send the message back to client
            sprintf(response, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n");
            int rsp_length = strlen(response);
            for (i=0; i<rsp_length; i++) {
                write(cs, &response[i], 1);
            }
            for (i=0; i<file_size; i++) {
                write(cs, &tmp[i], 1);
            }
            printf("Send Success, rsp_size: %d\n", rsp_length + file_size);
            fflush(stdout);
            free(tmp);
            fclose(fp);
        }
        else { // target file does not exist
            // send the message back to client
            sprintf(response, "HTTP/1.1 404 File Not Found\r\nConnection: Close\r\n\r\n");
            if (send(cs, response, strlen(response), 0) < 0) {
                printf("send failed\n");
                return;
            }
            printf("File does not exist, rsp_size: %ld\n", strlen(response));
            fflush(stdout);
        }
    }
    else {
        // other request except GET
        sprintf(response, "HTTP/1.1 400 Bad Request\r\nConnection: Close\r\n\r\n");
        if (send(cs, response, strlen(response), 0) < 0) {
            printf("send failed\n");
            return;
        }
        printf("Other Request, rsp_size: %ld\n", strlen(response));
        fflush(stdout);
    }
    close(cs);
}

int main(int argc, char *argv[])
{
    int s, cs;
    struct sockaddr_in server, client;

    // check argument
    if (argc != 2) {
        printf("argument error\n");
		return -1;
    }
    char *input = argv[1];
    int port = 0;
    while (*input != '\0') {
        if (*input >= '0' && *input <= '9') {
            port = port * 10 + (*input - '0');
            input++;
        }
        else{
            printf("input is not a number\n");
		    return -1;
        }
    }
     
    // create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("create socket failed");
		return -1;
    }
    printf("socket created\n");
    fflush(stdout);
     
    // prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);
     
    // bind
    if (bind(s,(struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("bind failed");
        return -1;
    }
    printf("bind done\n");
    fflush(stdout);
     
    // listen
    listen(s, port);
    printf("waiting for incoming connections... port: %d\n", port);
    fflush(stdout);
     
    // accept connection from an incoming client
    while(1){
        int c = sizeof(struct sockaddr_in);
        if ((cs = accept(s, (struct sockaddr *)&client, (socklen_t *)&c)) < 0) {
            perror("accept failed");
            return -1;
        }
        printf("connection accepted\n");
        fflush(stdout);
        handle_request(cs);
    }
    return 0;
}

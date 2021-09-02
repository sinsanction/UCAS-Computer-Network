#include "tcp_sock.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>

#define SEND_ONCE_SIZE 10000

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	char *rbuf = malloc(SEND_ONCE_SIZE + 1);
	char wbuf[1024];
	int rlen = 0;
	FILE *fp = fopen("server-output.dat","wb");
	int write_len = 0;
	int num = 0;
	
	while (1) {
		rlen = tcp_sock_read(csk, rbuf, SEND_ONCE_SIZE);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		} 
		else if (rlen > 0) {
			write_len = fwrite(rbuf, 1, rlen, fp);
			if (write_len != rlen) {
				log(ERROR, "write: %d, rlen: %d", write_len, rlen);
				exit(1);
			}
			log(DEBUG, "write: %d", write_len);

			num += write_len;
			sprintf(wbuf, "server echoes: recv ok (%d)", num);			
			if (tcp_sock_write(csk, wbuf, strlen(wbuf)) < 0) {
				log(DEBUG, "tcp_sock_write return negative value, something goes wrong.");
				exit(1);
			}
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
	}

	log(DEBUG, "close this connection.");

	tcp_sock_close(csk);

	fclose(fp);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	FILE *fp = fopen("client-input.dat", "r");
	fseek(fp, 0, SEEK_END);
	int dlen = ftell(fp);
	char *wbuf = malloc(dlen+1);
	fseek(fp, 0, SEEK_SET);
	fread(wbuf, 1, dlen, fp);

	char rbuf[1001];
	int rlen = 0;
	int remain_len = dlen;
	int send_ptr = 0;
	int send_len;

	while (remain_len > 0) {
		send_len = min(remain_len, SEND_ONCE_SIZE);
		if (tcp_sock_write(tsk, &wbuf[send_ptr], send_len) < 0) {
			log(ERROR, "socket write failed");
			break;
		}

		send_ptr += send_len;
		remain_len -= send_len;
		log(DEBUG, "send: %d, remain: %d, total: (%d/%d)", send_len, remain_len, send_ptr, dlen);

		usleep(50000);

		rlen = tcp_sock_read(tsk, rbuf, 1000);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		}
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			fprintf(stdout, "%s\n", rbuf);
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
	}

	tcp_sock_close(tsk);

	free(wbuf);

	fclose(fp);

	return NULL;
}

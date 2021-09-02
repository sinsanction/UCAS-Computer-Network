#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

struct list_head timer_list;
struct list_head retrans_timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	struct tcp_timer *time_entry = NULL, *time_q = NULL;
	list_for_each_entry_safe(time_entry, time_q, &timer_list, list) {
		if (time_entry->enable == 1 && time_entry->type == 0 && ((time(NULL) - time_entry->timeout) > TCP_TIMEWAIT_TIMEOUT / 1000000)) {
			struct tcp_sock *tsk = timewait_to_tcp_sock(time_entry);
			list_delete_entry(&time_entry->list);
			tcp_set_state(tsk, TCP_CLOSED);
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	//fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	tsk->timewait.type = 0;
	tsk->timewait.enable = 1;
	tsk->timewait.timeout = time(NULL);
	list_add_tail(&tsk->timewait.list, &timer_list);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}

// set the restrans timer of a tcp sock, by adding the timer into timer_list
void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	if (tsk->retrans_timer.enable) {
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		return;
	}
	tsk->retrans_timer.type = 1;
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->retrans_timer.retrans_time = 0;
	init_list_head(&tsk->retrans_timer.list);
	list_add_tail(&tsk->retrans_timer.list, &retrans_timer_list);
}

void tcp_update_retrans_timer(struct tcp_sock *tsk)
{
	if (list_empty(&tsk->send_buf) && tsk->retrans_timer.enable) {
		tsk->retrans_timer.enable = 0;
		list_delete_entry(&tsk->retrans_timer.list);
		wake_up(tsk->wait_send);
	}
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->retrans_timer.list)) {
		tsk->retrans_timer.enable = 0;
		list_delete_entry(&tsk->retrans_timer.list);
		wake_up(tsk->wait_send);
	}
	else {
		log(ERROR, "unset an empty retrans timer\n");
	}
}

void tcp_scan_retrans_timer_list(void)
{
	struct tcp_sock *tsk;
	struct tcp_timer *time_entry, *time_q;

	list_for_each_entry_safe(time_entry, time_q, &retrans_timer_list, list) {
		time_entry->timeout -= TCP_RETRANS_SCAN_INTERVAL;
		tsk = retranstimer_to_tcp_sock(time_entry);
		if (time_entry->timeout <= 0) {
			if(time_entry->retrans_time >= MAX_RETRANS_NUM && tsk->state != TCP_CLOSED){
				list_delete_entry(&time_entry->list);
				if (!tsk->parent) {
					tcp_unhash(tsk);
				}	
				wait_exit(tsk->wait_connect);
				wait_exit(tsk->wait_accept);
				wait_exit(tsk->wait_recv);
				wait_exit(tsk->wait_send);
				
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_send_control_packet(tsk, TCP_RST);
			}
			else if (tsk->state != TCP_CLOSED) {
				log(DEBUG, "retrans time: %d\n", time_entry->retrans_time + 1);
				tsk->ssthresh = max(((u32)(tsk->cwnd / 2)), 1);
				tsk->cwnd = 1;
				tsk->nr_state = LOSS;
				tsk->loss_point = tsk->snd_nxt;
				time_entry->retrans_time += 1;
				time_entry->timeout = TCP_RETRANS_INTERVAL_INITIAL * (1 << time_entry->retrans_time);
				tcp_retrans_send_buffer(tsk);
			}
		}
	}
}

void *tcp_retrans_timer_thread(void *arg)
{
	init_list_head(&retrans_timer_list);
	while(1){
		usleep(TCP_RETRANS_SCAN_INTERVAL);
		tcp_scan_retrans_timer_list();
	}

	return NULL;
}
/*
void *tcp_cwnd_thread(void *arg) {
	struct tcp_sock *tsk = (struct tcp_sock *)arg;
	FILE *fp = fopen("cwnd.txt", "w");
	struct timeval start;
    struct timeval end;
	gettimeofday(&start, NULL);

	int time_us = 0;
	while (tsk->state == TCP_ESTABLISHED && time_us < 10000000) {
		gettimeofday(&end, NULL);
		time_us = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
		fprintf(fp, "%d %f %f\n", time_us, tsk->cwnd, tsk->cwnd * TCP_MSS);
		usleep(100);
	}
	fclose(fp);
	return NULL;
}
*/
void *tcp_cwnd_thread(void *arg) {
	struct tcp_sock *tsk = (struct tcp_sock *)arg;
	FILE *fp = fopen("cwnd.txt", "w");
	
	int time_us = 0;
	while (tsk->state == TCP_ESTABLISHED && time_us < 1000000) {
		usleep(500);
		time_us += 500;
		fprintf(fp, "%d %f %f\n", time_us, tsk->cwnd, tsk->cwnd * TCP_MSS);
	}
	fclose(fp);
	return NULL;
}
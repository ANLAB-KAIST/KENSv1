#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <assert.h>

#include "kernel.h"
#include "kip.h"
#include "route.h"
#include "ktcp.h"
#include "linked_list.h"

#include "misc.h"
#include "log.h"

#include "kmgmt.h"
#include "kxml.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

//#define TCP_RELI /* Remove "//" for Assignment #2 */
//#define TCP_RETR /* Remove "//" for Assignment #3 */
//#define TCP_AIMD /* Remove "//" for Assignment #4 */

#if defined(_WIN32)
	typedef unsigned int tcp_seq;
	typedef unsigned short u_int16_t;
	typedef unsigned char u_int8_t;
	struct tcphdr
	{
		u_int16_t th_sport;		/* source port */
		u_int16_t th_dport;		/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_int8_t th_x2:4;		/* (unused) */
		u_int8_t th_off:4;		/* data offset */
		u_int8_t th_flags;
	#  define TH_FIN	0x01
	#  define TH_SYN	0x02
	#  define TH_RST	0x04
	#  define TH_PUSH	0x08
	#  define TH_ACK	0x10
	#  define TH_URG	0x20
		u_int16_t th_win;		/* window */
		u_int16_t th_sum;		/* checksum */
		u_int16_t th_urp;		/* urgent pointer */
	};
	int gettimeofday(struct timeval *tv, struct timezone *tz) {
		return 0;
	}
	#define write(s,b,l) send(s,b,l,0)
	#define read(s,b,l) recv(s,b,l,0)
#else
	#include <netinet/tcp.h>
#endif


/**************************************************************************/
/*                     Definition of Local Types                          */
/**************************************************************************/

#define SHS (sizeof(struct tcphdr)) /* TCP header size. */
#define MPS (536 - 20) /* Maximum payload size. */
#define MSS (SHS + MPS) /* Maximum segment size. */
#define MSL (120) /* Maximum segment lifetime (RFC793 specifies as 2 minutes). */
#define DEFAULT_NEXT_PORT (3000)
#define DEFAULT_WINDOW_SIZE (3072) /* Default window size. */
#define MAX_TRIAL (10) /* Maximum transmission trials. */

/* Connection states. */
enum {
	CSTATE_CLOSED = 0,
	CSTATE_LISTEN = 1,
	CSTATE_SYN_SENT = 2,
	CSTATE_SYN_RECV = 3,
	CSTATE_ESTABLISHED = 4,
	CSTATE_FIN_WAIT1 = 5,
	CSTATE_FIN_WAIT2 = 6,
	CSTATE_CLOSING = 7,
	CSTATE_TIME_WAIT = 8,
	CSTATE_CLOSE_WAIT = 9,
	CSTATE_LAST_ACK = 10
};

const char *CSTATE_strs[] = {
	"CSTATE_CLOSED",
	"CSTATE_LISTEN",
	"CSTATE_SYN_SENT",
	"CSTATE_SYN_RECV",
	"CSTATE_ESTABLISHED",
	"CSTATE_FIN_WAIT1",
	"CSTATE_FIN_WAIT2",
	"CSTATE_CLOSING",
	"CSTATE_TIME_WAIT",
	"CSTATE_CLOSE_WAIT",
	"CSTATE_LAST_ACK"
};

typedef struct tcp_container_t {
	tcp_seq seq_num;
	u_char flags;
	tcp_seq data_length;
	char data[MPS];

	int last_sent; /* Unit of mtime. */
	int timeout; /* Unit of mtime. */
	int trial;
} tcp_container;

typedef struct tcp_stream_t {
	tcp_seq seq_num;
	tcp_seq ack_num;
	tcp_seq win;
	list container_list;
} tcp_stream;

typedef struct tcp_context_t {
	int state;	/* current state of this connection */

	struct sockaddr_in my_addr;		/* my IP address for this connection */
	struct sockaddr_in peer_addr;	/* peer IP address for this connection */

	bool is_bound;					/* is this socket is bound?
									   or a port number has been assigned to this socket? */

#define PIPE_NO_RD		0x40000000	/* data pipe can not be read */
#define PIPE_NO_WR		0x80000000	/* data pipe can not be written */
#define PIPE_NO_RDWR	(PIPE_NO_RD|PIPE_NO_WR)
#define PIPE_CLOSED		PIPE_NO_RDWR	/* data pipe has been closed */
#define PIPE_FD(x)		(int)((x) & (~PIPE_CLOSED))	/* extract file descriptor
										from pipe variable */
	int pipe;					/* data pipe passed from kernel simulator */

	route ro;					/* routing table cache.
								   just pass it to IP layer */
	
	/* belows are ONLY used in server or passive socket */
	struct tcp_context_t *bind_ctx; /* server socket which listens TCP connection */
	int backlog;					/* the size of listen queue */
	list pending_ctx_list;			/* on handshaking connections */
	list accept_pending_ctx_list;	/* established connections */

	int timeout;
	int estimated_rtt;
	tcp_stream my_stream;
	tcp_stream peer_stream;

	int snd_cwnd;
	int snd_ssthresh;
	int t_dupacks;
	/* write your own variables below */

} tcp_context;

typedef struct tcp_segment_t {
	struct tcphdr header;
	char data[MPS];
	tcp_seq length;
} /*__attribute__ ((packed))*/ tcp_segment;

struct ktcp_t ktcp;

/**************************************************************************/
/*                   Declaration of Local Functions                       */
/**************************************************************************/

void tcp_dispatch_timer();
bool tcp_dispatch_out();
tcp_context* tcp_create_ctx(struct in_addr src_addr, struct in_addr dest_addr, tcp_segment segment);
tcp_context* tcp_find_ctx(struct in_addr src_addr, struct in_addr dest_addr, tcp_segment segment);
int tcp_send_segment(const tcp_context *ctx, u_char flags, const void *data, size_t data_length, tcp_seq seq_num);
void tcp_change_state(tcp_context *ctx, tcp_segment *segment);
void tcp_cleanup_timewait_ctx(int now);
bool tcp_add_to_my_stream(tcp_context *ctx, u_char flags, const void *data, size_t data_length);
void tcp_send_stream();
void tcp_recv_segment(tcp_context *ctx, tcp_segment *segment);
void tcp_accept_peer_ack(tcp_context *ctx, tcp_segment *segment);
void tcp_accept_peer_syn(tcp_context *ctx, tcp_segment *segment);
void tcp_accept_peer_fin(tcp_context *ctx, tcp_segment *segment);
void tcp_add_to_peer_stream(tcp_context *ctx, tcp_segment *segment);
void tcp_recv_stream();
void tcp_retransmit(tcp_context *ctx);
u_short tcp_checksum(struct in_addr src_addr, struct in_addr dest_addr, const tcp_segment *segment);

int tcp_get_mtime();
void tcp_debug_segment(char *title, struct in_addr src_addr, struct in_addr dest_addr, const tcp_segment *segment);

#define MIN(x,y)  ((x) <= (y) ? (x) : (y))
#define MAX(x,y)  ((x) >= (y) ? (x) : (y))

/**************************************************************************/
/*                  Implementation of Exposed Functions                   */
/**************************************************************************/

#ifdef HAVE_KMGMT
static int tcp_kmgmt_handler (int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values);
#endif /* HAVE_KMGMT */

/**
 * initialize TCP layer. You should initialize all global contexts such as
 * queues and variables in this function.
 * @return true when initialization process was successful
 */
bool tcp_startup(void)
{
	ktcp.allocated_ctx_list = list_open();
	ktcp.bind_ctx_list = list_open();
	ktcp.conn_ctx_list = list_open();
	ktcp.pending_ctx_list = list_open();
	ktcp.async_pending_ctx_list = list_open();
	ktcp.timewait_ctx_list = list_open();
	ktcp.next_port = DEFAULT_NEXT_PORT;
#ifdef HAVE_KMGMT
	ktcp.all_ctx_list = list_open();

	/* register for kmgmt */
	kmgmt_register (KMOD_TCP, KXML_MOD_TCP, tcp_kmgmt_handler);
#endif /* HAVE_KMGMT */

	return true;
}

/**
 * shutdown and clean up TCP layer. You should close all allocated sockets and
 * free all of them.
 */
void tcp_shutdown(void)
{
#ifdef HAVE_KMGMT
	list_close(ktcp.all_ctx_list);
#endif /* HAVE_KMGMT */
	list_close(ktcp.allocated_ctx_list);
	list_close(ktcp.bind_ctx_list);
	list_close(ktcp.conn_ctx_list);
	list_close(ktcp.pending_ctx_list);
	list_close(ktcp.async_pending_ctx_list);
	list_close(ktcp.timewait_ctx_list);
	return;
}

/**
 * when ksocket() system call is called by KENS application, kernel simulator
 * will invoke this function to allocate new TCP socket
 * @param err pointer to save the value of errno for KENS socket library
 * @return newly allocated TCP context
 */
tcp_socket tcp_open(int *err)
{
	tcp_context *ctx;

	ctx = (tcp_context *)malloc(sizeof(tcp_context));
	if ( ctx == NULL ) {
		*err = ENOMEM;
		return NULL;
	}
	memset(ctx, 0, sizeof(tcp_context));
	ctx->pipe = -1;

	list_add_tail(ktcp.allocated_ctx_list, ctx);
#ifdef HAVE_KMGMT
	list_add_tail(ktcp.all_ctx_list, ctx);
#endif /* HAVE_KMGMT */

	T_TCP_CB("(%08x) ksocket allocated",ctx);

	return ctx;
}

/**
 * ----- Assignment #2 -----
 * when kclose() system call is called by KENS application, kernel simulator
 * will invoke this function to do appropriate action on closing specified
 * socket
 * @param handle TCP context returned by tcp_open()
 * @param err pointer to save the value of errno for KENS socket library
 * @return true when success
 */
bool tcp_close(tcp_socket handle,int *err)
{
	return true;
}

/**
 * ----- Assignment #1 -----
 * when kbind() system call is called by KENS application, kernel simulator
 * will invoke this function to do appropriate action for bind
 * @param handle TCP context returned by tcp_open()
 * @param my_addr the address to bind
 * @param addrlen length of my_addr
 * @param err pointer to save the value of errno for KENS socket library
 * @return true when success
 */
bool tcp_bind(tcp_socket handle, const struct sockaddr *my_addr, socklen_t addrlen, int *err)
{
	return true;
}

/**
 * ----- Assignment #1 -----
 * when klisten() system call is called by KENS application, kernel simulator
 * will invoke this function to do appropriate action for listen
 * @param handle TCP context returned by tcp_open()
 * @param backlog the size of listen queue
 * @param err pointer to save the value of errno for KENS socket library
 * @return true when success
 */
bool tcp_listen(tcp_socket handle, int backlog, int *err)
{
	return true;
}

/**
 * ----- Assignment #1 -----
 * when kaccept() system call is called by KENS application, kernel simulator
 * will invoke this function to do appropriate action for accept
 * @param bind_handle TCP context returned by tcp_open() for passive KENS
 * socket
 * @param conn_handle TCP context returned by tcp_open() for using actual
 * communication
 * @param pipe data pipe which is bound to conn_handle
 * @param err pointer to save the value of errno for KENS socket library
 * @return true when success
 */
bool tcp_accept(tcp_socket bind_handle,tcp_socket conn_handle, int pipe, int *err)
{
	return true;
}

/**
 * ----- Assignment #1 -----
 * when kconnect() system call is called by KENS application, kernel simulator
 * will invoke this function to do appropriate action for connect
 * @param handle TCP context returned by tcp_open()
 * @param serv_addr server address to connect
 * @param addrlen length of serv_addr
 * @param pipe data pipe which is bound to conn_handle
 * @param err pointer to save the value of errno for KENS socket library
 * @return true when success
 */
bool tcp_connect(tcp_socket handle, const struct sockaddr *serv_addr, socklen_t addrlen, int pipe, int *err)
{
	return true;
}

/**
 * when kgetsockname() system call is called by KENS application, kernel simulator
 * will invoke this function to do appropriate action for getsockname
 * @param handle TCP context returned by tcp_open()
 * @param name pointer to sockaddr where save current socket address
 * @param namelen length of allocated buffer 'name'
 * @param err pointer to save the value of errno for KENS socket library
 * @return true when success
 */
bool tcp_getsockname(tcp_socket handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
	if ((handle == NULL) || (name == NULL) || (*namelen < 8)) {
		*err = EBADF;
		return false;
	}
	*namelen = MIN(sizeof(struct sockaddr_in), *namelen);
	memcpy(name, &((tcp_context *)handle)->my_addr, *namelen);
	return true;
}

/**
 * when kgetpeername() system call is called by KENS application, kernel simulator
 * will invoke this function to do appropriate action for getpeername
 * @param handle TCP context returned by tcp_open()
 * @param name pointer to sockaddr where save peer address of current socket
 * @param namelen length of allocated buffer 'name'
 * @param err pointer to save the value of errno for KENS socket library
 * @return true when success
 */
bool tcp_getpeername(tcp_socket handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
	if ((handle == NULL) || (name == NULL) || (*namelen < 8)) {
		*err = EBADF;
		T_TCP_CB("tcp_getpeername  handle = %08x namelen = %d",handle,*namelen);
		return false;
	}
	*namelen = MIN(sizeof(struct sockaddr_in), *namelen);
	memcpy(name, &((tcp_context *)handle)->peer_addr, *namelen);
	return true;
}

/**
 * this function is called by kernel simulator and do many things for
 * TCP layer such as managing connections, retrieving/sending data
 * from/to KENS application and serving for KENS applications' system calls
 * @return currently always returns true
 */
bool tcp_dispatch(void)
{
	/* nothing to schedule. small optimization for router */
	if ( list_get_count(ktcp.allocated_ctx_list) == 0 )
		return true;

	tcp_dispatch_pending();	/* return results of asynchronous calls
							   from kernel simulator. may be connect()
							 or accept... :-) */
	tcp_dispatch_timer();	/* update timers and do retransmission */
#ifdef TCP_RELI
	tcp_dispatch_out();		/* read data from KENS applications and send data 
							 via IP layer */
#endif

#ifdef TCP_RETR
	tcp_send_stream();
#endif

	return true;
}

/**
 * whenever a new TCP packet is delivered by IP layer, this function is called
 * to let TCP layer handle it. You should select appropriate established
 * socket context and send payload to KENS application via data pipe.
 * @param src_addr the packet's source IP address
 * @param dest_addr the packet's destination IP address
 * @param buf payload
 * @param count size of payload
 * @return true when the packet is successfully handled, false otherwise
 */
bool tcp_dispatch_in(struct in_addr src_addr, struct in_addr dest_addr, const void *buf, size_t count)
{
	tcp_context *related_ctx;
	tcp_context *bind_ctx;
	tcp_segment segment;
	list_position pos;
	int err;

	/* Validate parameters. */
	if ((src_addr.s_addr == 0) || (dest_addr.s_addr == 0) || (count < SHS) || (count > MSS)) {
		char buf[80];
		inet_ntoa_r(src_addr,buf,80);
		T_TCP("invalid arguments to tcp_dispatch_in");
		T_TCP("src = %s dst = %s count = %d",
				buf,
				inet_ntoa(dest_addr),
				count
		);
		return false;
	}

	/* Convert data to a segment. */
	memcpy(&segment.header, buf, count);

	/* Set the segment length. */
	segment.length = (u_short)count;

	if ( kens_log_flag & (LOG_TCP_HDR|LOG_TCP_PKT) )
		tcp_debug_segment("receive TCP segment",src_addr, dest_addr, &segment);

	/* Check the header length. */
	if (((segment.header.th_off * 4) < SHS) || ((segment.header.th_off * 4) > (signed)segment.length)) {
		T_TCP("invalid header size");
		return false;
	}

#ifdef TCP_RETR
	/* Check the checksum of TCP header. */
	if (tcp_checksum(src_addr, dest_addr, &segment) != segment.header.th_sum) {
		T_TCP("invalid checksum : calculated = %d received = %d",
				tcp_checksum(src_addr,dest_addr,&segment),
				segment.header.th_sum
		);
		return false;
	}
#endif

	/* Discard the segment that has two among SYN, FIN, and RST at once. */
	if (((segment.header.th_flags & TH_SYN) && ((segment.header.th_flags & TH_FIN) || (segment.header.th_flags & TH_RST))) ||
		((segment.header.th_flags & TH_FIN) && (segment.header.th_flags & TH_RST))) {
		T_TCP("invalid header flags");
		return false;
	}

	if ((related_ctx = tcp_find_ctx(src_addr, dest_addr, segment)) != NULL) {
#ifdef TCP_RETR
		tcp_recv_segment(related_ctx, &segment);
#else
		tcp_change_state(related_ctx, &segment);
#endif
		return true;
	}

	if (segment.header.th_flags & TH_SYN) {
		if ((related_ctx = tcp_create_ctx(src_addr, dest_addr, segment)) != NULL) {
#ifdef TCP_RETR
		tcp_recv_segment(related_ctx, &segment);
#else
		tcp_change_state(related_ctx, &segment);
#endif
			return true;
		}
	}

	return false;
}

/**
 * ----- Assignment #1 -----
 * each dispatch loop, there might be some connections the states of which
 * have been changed recently. This function is called for the first time in
 * TCP dispatch steps and notify recently changed connections to kernel
 * simulator. For example, newly established connection or newly accepted
 * connection should be notified to kernel simulator to return result to KENS
 * application which is blocked by kconnect() or kaccept()
 */
void tcp_dispatch_pending(void)
{
}

/**
 * each dispatch loop, TCP should update timers to retransmit packets.
 */
void tcp_dispatch_timer()
{
	list_position pos;
	tcp_context *ctx;
	
#ifdef TCP_RELI
	tcp_cleanup_timewait_ctx(tcp_get_mtime());
#endif

#ifdef TCP_RETR
	/* do retransmission */

	/* Fixed the bug that handshaking packets are not retransmitted */
	pos = list_get_head_position(ktcp.pending_ctx_list);
	while ( pos != NULL ) {
		ctx = list_get_next(&pos);
		tcp_retransmit(ctx);
	}

	pos = list_get_head_position(ktcp.conn_ctx_list);
	while ( pos != NULL ) {
		ctx = list_get_next(&pos);
		tcp_retransmit(ctx);
	}

#endif
}

/**
 * read data from KENS applications and send them to peer
 */
bool tcp_dispatch_out()
{
	fd_set fds;
	struct timeval timeout;
	int max_fd, err;
	tcp_context *ctx;
	list_position pos;
	char buf[MPS];
	int data_length;

	if (list_get_count(ktcp.conn_ctx_list) == 0)
		return true;

	max_fd = -1;
	FD_ZERO(&fds);
	pos = list_get_head_position(ktcp.conn_ctx_list);
	while (pos != NULL) {
		ctx = list_get_next(&pos);
		if ( (ctx->pipe & PIPE_NO_RD) != 0 ) continue;
		max_fd = MAX(max_fd, PIPE_FD(ctx->pipe));
		FD_SET(PIPE_FD(ctx->pipe), &fds);
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = 1000; /* Set 1 msec. */

	switch (select(max_fd + 1, &fds, NULL, NULL, &timeout)) {
		case -1:
			T_TCP("(%08x) pipe to application has been closed %s",
					ctx,
					( data_length == 0 ) ? "" : strerror(errno)
			);
			return false;
		case 0:
			break;
		default:
			pos = list_get_head_position(ktcp.conn_ctx_list);
			while (pos != NULL) {
				ctx = list_get_next(&pos);
				if ( (ctx->pipe & PIPE_NO_RD) == 0
						&& FD_ISSET(PIPE_FD(ctx->pipe), &fds)) {
					data_length = read(PIPE_FD(ctx->pipe), buf, MPS);

					T_TCP("(%08x) %d bytes data from application",ctx,data_length);

					if ( data_length <= 0 ) {
						/* connection upruptly closed by application */
						/* call tcp_close and let kernel knows the socket has
						 * been closed
						 */
						T_TCP("(%08x) pipe to application has been closed %s",
								ctx,
								( data_length == 0 ) ? "" : strerror(errno)
						);
						tcp_close(ctx,&err);
					} else {
						T_TCP("(%08x) %d bytes from application",ctx,data_length);
#ifdef TCP_RETR
						tcp_add_to_my_stream(ctx, TH_ACK, buf, data_length);
#else
						tcp_send_segment(ctx, TH_ACK, buf, data_length, 0);
#endif
					}
				}
			}
			break;
	}

	return true;
}

/**************************************************************************/
/*                  Implementation of Local Functions                     */
/**************************************************************************/

/**
 * ----- Assignment #1 -----
 * Find the listening context related to a SYN segment in the bound server list
 * and create a new context which handles new connection.
 * @param src_addr the packet's source IP address
 * @param dest_addr the packet's destination IP address
 * @param segment tcp_segment made from incoming TCP packet
 * @return newly created TCP context
 */
tcp_context* tcp_create_ctx(struct in_addr src_addr, struct in_addr dest_addr, tcp_segment segment)
{
	return NULL;
}

/**
 * ----- Assignment #1 -----
 * Find the context related to a segment in the ktcp list
 * @param src_addr the packet's source IP address
 * @param dest_addr the packet's destination IP address
 * @param segment TCP segment made from incoming TCP packet
 * @return TCP context related to a segment
 */
tcp_context* tcp_find_ctx(struct in_addr src_addr, struct in_addr dest_addr, tcp_segment segment)
{
	return NULL;
}

/**
 * ----- Assignment #1 -----
 * Make a TCP segment and send it to IP layer
 * ----- Assignment #2 -----
 * Copy parameter 'data' to segment's payload
 * ----- Assignment #3 -----
 * Set appropriate values to segment's seq/ack/sum field
 * @param ctx TCP context
 * @param flags new segment's flags
 * @param data payload
 * @param data_length size of payload
 * @param seq_num new segment's th_seq
 * @return return value of ip_output
 */
int tcp_send_segment(const tcp_context *ctx, u_char flags, const void *data, size_t data_length, tcp_seq seq_num)
{
	tcp_segment segment;

	return ip_output(ctx->my_addr.sin_addr, ctx->peer_addr.sin_addr, &segment, segment.length, NULL);
}

/**
 * ----- Assignment #1 -----
 * Manage state transition of a context when a segment comes
 * (only for 3-way handshaking case)
 * ----- Assignment #2 -----
 * Fully implement TCP state transition diagram
 * @param ctx TCP context
 * @param segment TCP segment
 */
void tcp_change_state(tcp_context *ctx, tcp_segment *segment)
{
	u_char flags = segment->header.th_flags;
	tcp_seq data_length = segment->length - (segment->header.th_off * 4);

	switch (ctx->state) {
		case CSTATE_ESTABLISHED:
			if (flags != TH_FIN) {
#ifndef TCP_RETR /* only for Assignment #2 */
				if ( !(ctx->pipe & PIPE_NO_WR) )
					write(PIPE_FD(ctx->pipe), segment->data, data_length);
#endif
			}
			break;
	}
}

/**
 * ----- Assignment #2 -----
 * Cleanup time_wait connections
 * @param now time used to check context's timeout
 */
void tcp_cleanup_timewait_ctx(int now)
{
}

/**
 * ----- Assignment #3 -----
 * Make a new container and add to container list of my stream
 * @param ctx TCP context
 * @param flags new segment's flags
 * @param data payload
 * @param data_length size of payload
 * @return true when success
 */
bool tcp_add_to_my_stream(tcp_context *ctx, u_char flags, const void *data, size_t data_length)
{
	return true;
}

/**
 * ----- Assignment #3 -----
 * In each dispatch loop, containers in my stream should be sended to IP layer.
 * For handshaking and established TCP contexts, containers in send window are
 * transmitted in this function.
 * ----- Assignment #4 -----
 * You should consider congestion window also.
 */
void tcp_send_stream()
{
}

void tcp_recv_segment(tcp_context *ctx, tcp_segment *segment)
{
	tcp_seq seq_num;
	tcp_seq data_length;

	/* Accept acknowledgment of my stream by peer. */
	if (segment->header.th_flags & TH_ACK)
		tcp_accept_peer_ack(ctx, segment);

	/* Get information of received segment. */
	seq_num = ntohl(segment->header.th_seq);
	data_length = segment->length - (segment->header.th_off * 4);

	/* Accept SYN of the peer stream. */
	if (segment->header.th_flags & TH_SYN) {
		tcp_accept_peer_syn(ctx, segment);
		tcp_change_state(ctx, segment);
	}

	if (ctx->peer_stream.container_list == NULL) /* Not yet receive SYN, so discard it. */
		return;

	/* Accept FIN of the peer stream. */
	if (segment->header.th_flags & TH_FIN && ctx->peer_stream.ack_num == seq_num) {
		tcp_accept_peer_fin(ctx, segment);
		tcp_change_state(ctx, segment);
	}

	/* Accept ACK of handshaking or connection teardown. */
	if (segment->header.th_flags & TH_ACK && data_length == 0)
		tcp_change_state(ctx, segment);

	if (data_length > 0) {
		/* Add segment to the peer stream. */
		tcp_add_to_peer_stream(ctx, segment);
		tcp_change_state(ctx, segment);
		tcp_add_to_my_stream(ctx, TH_ACK, NULL, 0);
	}
}

/**
 * ----- Assignment #3 -----
 * When ACK is received, send window must be slided using segment's ack_num
 * and estimated rtt have to be updated.
 * ----- Assignment #4 -----
 * When duplicated ACK happens, congestion window size is decreased.
 * Otherwise, congestion window size is increased.
 * @param ctx TCP context
 * @param segment TCP segment
 */
void tcp_accept_peer_ack(tcp_context *ctx, tcp_segment *segment)
{
}

/**
 * ----- Assignment #3 -----
 * When ctx's state can accept SYN, peer_stream must be initialized.
 * @param ctx TCP context
 * @param segment TCP SYN segment
 */
void tcp_accept_peer_syn(tcp_context *ctx, tcp_segment *segment)
{
}

/**
 * ----- Assignment #3 -----
 * When ctx's state can accept FIN, update peer_stream.ack_num
 * @param ctx TCP context
 * @param segment TCP FIN segment
 */
void tcp_accept_peer_fin(tcp_context *ctx, tcp_segment *segment)
{
}

/**
 * ----- Assignment #3 -----
 * If segment has payload and in order, new container is created
 * and inserted into receive buffer
 * @param ctx TCP context
 * @param segment TCP segment
 */
void tcp_add_to_peer_stream(tcp_context *ctx, tcp_segment *segment)
{
}

/**
 * ----- Assignment #3 -----
 * In each dispatch loop, containers in peer stream should be delivered
 * to KENS application. For all established TCP contexts, data in receive
 * buffer are transmitted in this function.
 */
void tcp_recv_stream()
{
}

/**
 * ----- Assignment #3 -----
 * if a timer expires, TCP should retransmit packets to the peer.
 * The timeout value is calculated from estimated round trip time.
 * In this function, you should implement a mechanism which updates and
 * maintain timer information and retransmission of currently
 * established sockets
 * ----- Assignment #4 -----
 * You should consider congestion window when retransmitting.
 * 
 */
void tcp_retransmit(tcp_context *ctx)
{
}

/**
 * ----- Assignment #3 -----
 * Calculate a segment's checksum.
 * @param src_addr the packet's source IP address
 * @param dest_addr the packet's destination IP address
 * @param segment TCP segment
 * @return checksum
 */
u_short tcp_checksum(struct in_addr src_addr,struct in_addr dest_addr, const tcp_segment *segment)
{
	return htonl(0);
}

/*
 * You can use this function to get the time.
 */
int tcp_get_mtime()
{
	static struct timeval begin_tv = { 0, 0 };
	struct timeval curr_tv;

	if (begin_tv.tv_sec == 0) {
		gettimeofday(&begin_tv, NULL);
		begin_tv.tv_sec = begin_tv.tv_sec - 1;
		begin_tv.tv_usec = 0; /* Ignore the usec of begin_it. */
	}

	gettimeofday(&curr_tv, NULL);
	return (((curr_tv.tv_sec - begin_tv.tv_sec) * 1000) + (curr_tv.tv_usec / 1000));
}

void tcp_debug_segment(char *title,struct in_addr src_addr, struct in_addr dest_addr, const tcp_segment *segment)
{
	u_short data_length;
	char buf[80];

	data_length = segment->length - (segment->header.th_off * 4);

	inet_ntoa_r(src_addr,buf,80);

	L_TCP_HDR(title);
	L_TCP_HDR("src = %s:%d dest = %s:%d data length = %d",
		buf, ntohs(segment->header.th_sport), 
		inet_ntoa(dest_addr), ntohs(segment->header.th_dport),
		data_length
	);

	/* we will uncover the macro */
	if ( kens_log_flag & LOG_TCP_HDR )
		LOG_print("TCP_HDR","  seq=%u ack=%u win=%u flags=%c%c%c%c%c%c",
				ntohl(segment->header.th_seq),
				ntohl(segment->header.th_ack),
				ntohs(segment->header.th_win),
				(segment->header.th_flags & TH_FIN ? 'F' : '_'),
				(segment->header.th_flags & TH_SYN ? 'S' : '_'),
				(segment->header.th_flags & TH_RST ? 'R' : '_'),
				(segment->header.th_flags & TH_PUSH? 'P' : '_'),
				(segment->header.th_flags & TH_ACK ? 'A' : '_'),
				(segment->header.th_flags & TH_URG ? 'U' : '_')
		);

	if (data_length > 0) {
		int i;
		char *p;

		memset(buf, ' ', 6);
		p = buf + 6;
		L_TCP_PKT("    printable data:");
		for (i = 0; (i < data_length) && (i < MPS); i ++) {
			if ((i % 64) == 0 && i != 0) {
				*p = '\0';
				L_TCP_PKT("%s",buf);
				p = buf + 6;
			}
			if ( isprint(segment->data[i]) )
				*p++ = segment->data[i];
			else
				*p++ = '.';
		}
		if ((i % 64) != 0) {
			*p = '\0';
			L_TCP_PKT("%s", buf);
		}
	}
	return;
}


#undef DEBUG

#ifdef DEBUG
#define DBG(x...) do { \
	fprintf (stderr, x); \
} while (0)
#else
#define DBG(x...)
#endif

/**
 * When KensG requests for TCP Contexts data, tcp_kmgmt_handler() is called.
 * TCP Context table maintains a dummy numerical index.
 *
 * @param	modid module id
 *			cmd either get/set
 *			table table name, currently only "context" is supported
 *			index index for the table.
 *			rindex for "get"
 *			nparam # of requested parameters
 *			nvalue # of returned parameters for "get"
 *			params list of requested parameters
 *			values list of returned parameters
 * @return  error code
 */
static int tcp_kmgmt_handler (int modid, int cmd, char *table, char *index, 
		char **rindex, int nparam, int *nvalue, list params, list values)
{
	list_position param_pos = NULL;

	n_linked_list_t *entry = NULL;
	kmgmt_param_t *inattr = NULL;
	kmgmt_param_t *outattr = NULL;

	list ctx_list = ktcp.all_ctx_list; // list of all tcp-contexts
	list_position ctx_pos;

	char *address = NULL;
	char *netmask = NULL;

	in_addr_t addr, mask;

#undef BUFSIZ
#define BUFSIZ	1024
	char buffer[BUFSIZ];

	if (cmd < 0 || cmd >= KMGMT_MAX)
	{
		return FAILED;
	}

	if (table != NULL && strcmp(table,"context") == 0)
	{
		if (cmd == KMGMT_SET)
		{
			DBG ("SET is not supported.\n");
			goto error;
		}

		/*
		 * iterate through tcp contexts
		 */
		int index = 0;

		for (ctx_pos = list_get_head_position(ctx_list);
				ctx_pos; ctx_pos = list_get_next_position(ctx_pos)) {

			tcp_context *ctx = list_get_at(ctx_pos);

			entry = NULL;
			inattr = NULL;
			outattr = NULL;

			if (cmd == KMGMT_GET)
			{
				entry = (n_linked_list_t*)malloc (sizeof(n_linked_list_t));
				entry->l = list_open();
				sprintf (buffer, "%d", ++index);
				entry->index = strdup (buffer);
			}

			param_pos = list_get_head_position (params);

			while (param_pos != NULL)
			{
				char *value = NULL;

				inattr = (kmgmt_param_t*)list_get_at (param_pos);
				if (!inattr)
					continue;

				if (!strcmp(inattr->param, "state"))
				{
					if (cmd == KMGMT_GET)
					{
						if (ctx->state < CSTATE_CLOSED ||
								ctx->state > CSTATE_LAST_ACK)
							sprintf (buffer, "UNKNOWN");
						else
							sprintf (buffer, "%s", CSTATE_strs[ctx->state]);

						value = strdup (buffer);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "my_address"))
				{
					if (cmd == KMGMT_GET)
					{
						/* note that by using inet_ntoa() this function is not reentrant. */
						sprintf (buffer, "%s:%d", inet_ntoa(ctx->my_addr.sin_addr),
								ntohs(ctx->my_addr.sin_port));
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "peer_address"))
				{
					if (cmd == KMGMT_GET)
					{
						/* note that by using inet_ntoa() this function is not reentrant. */
						sprintf (buffer, "%s:%d", inet_ntoa(ctx->peer_addr.sin_addr),
								ntohs(ctx->peer_addr.sin_port));
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "bound"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%s", ctx->is_bound?"true":"false");
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "backlog"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->backlog);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "timeout"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->timeout);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "estimated_rtt"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->estimated_rtt);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "snd_cwnd"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->snd_cwnd);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "snd_ssthresh"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->snd_ssthresh);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "t_dupacks"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->t_dupacks);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "my_seqnum"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->my_stream.seq_num);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "peer_seqnum"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->peer_stream.seq_num);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "peer_acknum"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->peer_stream.ack_num);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				else if (!strcmp(inattr->param, "peer_window_size"))
				{
					if (cmd == KMGMT_GET)
					{
						sprintf (buffer, "%d", ctx->peer_stream.win);
					}
					else if (cmd == KMGMT_SET)
					{
						DBG ("set method is not supported\n");
					}
				}
				/* Add your own variables */
				else
				{
					DBG ("Unknown parameter <%s>\n", inattr->param);
				}

				if (cmd == KMGMT_GET)
				{
					if (value != NULL)
					{
						outattr = (kmgmt_param_t*)malloc (sizeof(kmgmt_param_t));
						outattr->param = strdup (inattr->param);
						outattr->value = value;

						list_add_tail (entry->l, (void*)outattr);
					}
				}

				param_pos = list_get_next_position (param_pos);
			}

			if (entry != NULL)
				list_add_tail (values, (void*)entry);
		}


	}
	else
	{
		DBG ("Unknown Table\n");
	}

	return DONE;

error:
	return FAILED;
}

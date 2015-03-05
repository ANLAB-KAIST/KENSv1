#include <stdio.h>
#include "CuTest.h"
#include "ktcp.h"
#include "route.h"
#include "KtcpTest.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

extern struct ktcp_t ktcp;
static tcp_segment *segment;
static int trans_segment;
static char ker_msg;
static int ker_status;
static tcp_context *bind_handle;
static tcp_context *conn_handle;

CuSuite* KtcpGetSuite();
uint32_t ip_host_address(struct in_addr in);

void TestBind(CuTest *tc)
{
	tcp_socket handle;
	tcp_context *ctx, *bound_ctx;
	struct sockaddr_in my_addr;
	socklen_t addrlen;
	bool retValue;
	int i, err;

	handle = tcp_open(&err);
	ctx = (tcp_context *)handle;

	bound_ctx = tcp_open(&err);
	bound_ctx->my_addr.sin_port = 5858;
	bound_ctx->my_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
	list_add_tail(ktcp.bind_ctx_list, bound_ctx);

	/* address collision avoidance check */
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = 5858;
	my_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
	addrlen = sizeof(my_addr);
	retValue = tcp_bind(handle, (struct sockaddr *)&my_addr, addrlen, &err);
	CuAssertIntEquals(tc, false, retValue);

	/* state condition check */
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = 5959;
	my_addr.sin_addr.s_addr = inet_addr("192.168.2.2");
	addrlen = sizeof(my_addr);
	for(i=0; i<=CSTATE_CLOSING; i++) {
		if(i == CSTATE_CLOSED)
			continue;
		ctx->state = i;
		retValue = tcp_bind(handle, (struct sockaddr *)&my_addr, addrlen, &err);
		CuAssertIntEquals(tc, false, retValue);
	}

	/* normal case */
	ctx->state = CSTATE_CLOSED;
	retValue = tcp_bind(handle, (struct sockaddr *)&my_addr, addrlen, &err);
	CuAssertIntEquals(tc, true, retValue);
	CuAssertIntEquals(tc, true, ctx->is_bound);
	CuAssertIntEquals(tc, my_addr.sin_family, ctx->my_addr.sin_family);
	CuAssertIntEquals(tc, my_addr.sin_port, ctx->my_addr.sin_port);
	CuAssertLonEquals(tc, my_addr.sin_addr.s_addr, ctx->my_addr.sin_addr.s_addr);
	/* check: context in ktcp.bind_ctx_list */
	CuAssertPtrEquals(tc, ctx, list_get_tail(ktcp.bind_ctx_list));

	list_remove_all(ktcp.bind_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);
	free(bound_ctx);
}

void TestListen(CuTest *tc)
{
	tcp_socket handle;
	tcp_context *ctx;
	int backlog = 3;
	bool retValue;
	int err;

	/* return false if "is_bound" is false */
	handle = tcp_open(&err);
	ctx = (tcp_context *)handle;
	ctx->is_bound = false;
	retValue = tcp_listen(handle, backlog, &err);
	CuAssertIntEquals(tc, false, retValue);

	/* normal case */
	ctx->is_bound = true;
	retValue = tcp_listen(handle, backlog, &err);
	CuAssertIntEquals(tc, true, retValue);
	CuAssertIntEquals(tc, backlog, ctx->backlog);
	CuAssertIntEquals(tc, CSTATE_LISTEN, ctx->state);
	/* check: creating ctx->pending_ctx_list */
	/* check: creating ctx->accept_pending_ctx_list */
	CuAssertPtrNotNull(tc, ctx->pending_ctx_list);
	CuAssertPtrNotNull(tc, ctx->accept_pending_ctx_list);

	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);
}

void TestAccept(CuTest *tc)
{
	tcp_socket bind_handle, conn_handle;
	tcp_context *bind_ctx, *conn_ctx;
	bool retValue;
	int pipe, err, i;

	bind_handle = tcp_open(&err);
	bind_ctx = (tcp_context *)bind_handle;
	bind_ctx->is_bound = true;
	bind_ctx->accept_pending_ctx_list = list_open();
	conn_handle = tcp_open(&err);
	conn_ctx = (tcp_context *)conn_handle;
	pipe = 10;

	/* state condition check */
	for(i=0; i<=CSTATE_CLOSING; i++) {
		if(i == CSTATE_LISTEN)
			continue;
		bind_ctx->state = i;
		retValue = tcp_accept(bind_handle, conn_handle, pipe, &err);
		CuAssertIntEquals(tc, false, retValue);
	}

	/* normal case */
	bind_ctx->state = CSTATE_LISTEN;
	retValue = tcp_accept(bind_handle, conn_handle, pipe, &err);
	CuAssertIntEquals(tc, true, retValue);
	CuAssertIntEquals(tc, pipe, conn_ctx->pipe);
	CuAssertPtrEquals(tc, conn_handle, list_get_tail(bind_ctx->accept_pending_ctx_list));

	list_remove_all(ktcp.allocated_ctx_list);
	list_close(bind_ctx->accept_pending_ctx_list);
	free(bind_ctx);
	free(conn_ctx);
}

void TestConnect(CuTest *tc)
{
	tcp_socket handle;
	tcp_context *ctx;
	struct sockaddr_in serv_addr;
	socklen_t addrlen;
	bool retValue;
	int pipe, err, i;

	handle = tcp_open(&err);
	ctx = (tcp_context *)handle;
	pipe = 10;

	/* state condition check */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = 5959;
	serv_addr.sin_addr.s_addr = inet_addr("192.168.2.2");
	addrlen = sizeof(serv_addr);
	for(i=0; i<=CSTATE_CLOSING; i++) {
		if(i == CSTATE_CLOSED)
			continue;
		ctx->state = i;
		retValue = tcp_bind(handle, (struct sockaddr *)&serv_addr, addrlen, &err);
		CuAssertIntEquals(tc, false, retValue);
	}

	/* normal case */
	ctx->state = CSTATE_CLOSED;
	retValue = tcp_connect(handle, (struct sockaddr *)&serv_addr, addrlen, pipe, &err);
	CuAssertIntEquals(tc, true, retValue);
	CuAssertIntEquals(tc, serv_addr.sin_family, ctx->peer_addr.sin_family);
	CuAssertIntEquals(tc, serv_addr.sin_port, ctx->peer_addr.sin_port);
	CuAssertLonEquals(tc, serv_addr.sin_addr.s_addr, ctx->peer_addr.sin_addr.s_addr);
	CuAssertIntEquals(tc, pipe, ctx->pipe);
	CuAssertIntEquals(tc, CSTATE_SYN_SENT, ctx->state);
	CuAssertPtrEquals(tc, ctx, list_get_tail(ktcp.pending_ctx_list));
	CuAssertIntEquals(tc, AF_INET, ctx->my_addr.sin_family);
	/* ktcp.next_port를 이용 안할수도 있음 */
	/*CuAssertIntEquals(tc, htons(ktcp.next_port-1), ctx->my_addr.sin_port);*/
	CuAssertLonEquals(tc, ip_host_address(ctx->peer_addr.sin_addr), ctx->my_addr.sin_addr.s_addr);
	CuAssertIntEquals(tc, true, ctx->is_bound);
	/* check: ctx in ktcp.bind_ctx_list */
	CuAssertPtrEquals(tc, ctx, list_get_tail(ktcp.bind_ctx_list));

	list_remove_all(ktcp.pending_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
}

void TestSendSegment1(CuTest *tc)
{
	tcp_context *ctx;
	u_char flags;
	char data[MPS];
	size_t data_length;
	tcp_seq seq_num;
	bool retValue;
	int err, i;

	ctx = tcp_open(&err);
	ctx->my_addr.sin_port = 5050;
	ctx->peer_addr.sin_port = 6060;

	flags = TH_SYN|TH_ACK;
	memset(data, 1, MPS);
	data_length = sizeof(data);
	seq_num = 5;
	memset(segment, 0, sizeof(tcp_segment));

	retValue = tcp_send_segment(ctx, flags, data, data_length, seq_num);

	CuAssertIntEquals(tc, ctx->my_addr.sin_port, segment->header.th_sport);
	CuAssertIntEquals(tc, ctx->peer_addr.sin_port, segment->header.th_dport);
	CuAssertIntEquals(tc, (SHS + 3) / 4, segment->header.th_off);
	CuAssertIntEquals(tc, flags, segment->header.th_flags);
	CuAssertIntEquals(tc, htonl(seq_num), segment->header.th_seq);
	CuAssertIntEquals(tc, SHS + data_length, segment->length);

	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);
}

void TestSendSegment2(CuTest *tc)
{
	tcp_context *ctx;
	u_char flags;
	char data[MPS];
	size_t data_length;
	tcp_seq seq_num;
	bool retValue;
	int err, i;

	ctx = tcp_open(&err);
	ctx->my_addr.sin_port = 5050;
	ctx->peer_addr.sin_port = 6060;

	flags = TH_ACK;
	memset(data, 1, MPS);
	data_length = sizeof(data);
	seq_num = 5;
	memset(segment, 0, sizeof(tcp_segment));

	retValue = tcp_send_segment(ctx, flags, data, data_length, seq_num);
	for(i=0; i<data_length; i++)
		CuAssertIntEquals(tc, data[i], segment->data[i]);

	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);
}

void TestSendSegment3(CuTest *tc)
{
	tcp_context *ctx;
	u_char flags;
	char data[MPS];
	size_t data_length;
	tcp_seq seq_num;
	bool retValue;
	int err, i;

	ctx = tcp_open(&err);
	ctx->my_addr.sin_port = 5050;
	ctx->peer_addr.sin_port = 6060;

	flags = TH_ACK;
	memset(data, 1, MPS);
	data_length = sizeof(data);
	seq_num = 5;
	memset(segment, 0, sizeof(tcp_segment));

	retValue = tcp_send_segment(ctx, flags, data, data_length, seq_num);
	CuAssertIntEquals(tc, ctx->peer_stream.ack_num, ntohl(segment->header.th_ack));
	CuAssertIntEquals(tc, tcp_checksum(ctx->my_addr.sin_addr, ctx->peer_addr.sin_addr, segment), segment->header.th_sum);

	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);

}

void TestFindCtx(CuTest *tc)
{
	tcp_context *ctx, *related_ctx;
	struct in_addr src_addr, dest_addr;
	tcp_segment segment;
	int err;

	ctx = tcp_open(&err);
	ctx->peer_addr.sin_port = 5050;
	ctx->my_addr.sin_port = 6060;
	ctx->peer_addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	ctx->my_addr.sin_addr.s_addr = inet_addr("2.2.2.2");
	related_ctx = NULL;

	segment.header.th_sport = 5050;
	segment.header.th_dport = 6060;
	src_addr.s_addr = inet_addr("1.1.1.1");
	dest_addr.s_addr = inet_addr("2.2.2.2");

	/* normal case: when related_ctx is in conn_ctx_list */
	list_add_tail(ktcp.conn_ctx_list, ctx);
	related_ctx = (tcp_context *)tcp_find_ctx(src_addr, dest_addr, segment);
	CuAssertPtrNotNull(tc, related_ctx);
	CuAssertIntEquals(tc, segment.header.th_sport, related_ctx->peer_addr.sin_port);
	CuAssertIntEquals(tc, segment.header.th_dport, related_ctx->my_addr.sin_port);
	CuAssertLonEquals(tc, src_addr.s_addr, related_ctx->peer_addr.sin_addr.s_addr);
	CuAssertLonEquals(tc, dest_addr.s_addr, related_ctx->my_addr.sin_addr.s_addr);

	/* normal case: when related_ctx is in pending_ctx_list */
	list_remove_all(ktcp.conn_ctx_list);
	list_add_tail(ktcp.pending_ctx_list, ctx);
	related_ctx = (tcp_context *)tcp_find_ctx(src_addr, dest_addr, segment);
	CuAssertPtrNotNull(tc, related_ctx);
	CuAssertIntEquals(tc, segment.header.th_sport, related_ctx->peer_addr.sin_port);
	CuAssertIntEquals(tc, segment.header.th_dport, related_ctx->my_addr.sin_port);
	CuAssertLonEquals(tc, src_addr.s_addr, related_ctx->peer_addr.sin_addr.s_addr);
	CuAssertLonEquals(tc, dest_addr.s_addr, related_ctx->my_addr.sin_addr.s_addr);

	/* normal case: when related_ctx is in async_pending_ctx_list */
	list_remove_all(ktcp.pending_ctx_list);
	list_add_tail(ktcp.async_pending_ctx_list, ctx);
	related_ctx = (tcp_context *)tcp_find_ctx(src_addr, dest_addr, segment);
	CuAssertPtrNotNull(tc, related_ctx);
	CuAssertIntEquals(tc, segment.header.th_sport, related_ctx->peer_addr.sin_port);
	CuAssertIntEquals(tc, segment.header.th_dport, related_ctx->my_addr.sin_port);
	CuAssertLonEquals(tc, src_addr.s_addr, related_ctx->peer_addr.sin_addr.s_addr);
	CuAssertLonEquals(tc, dest_addr.s_addr, related_ctx->my_addr.sin_addr.s_addr);

	list_remove_all(ktcp.async_pending_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);
}

void TestCreateCtx(CuTest *tc)
{
	tcp_context *bind_ctx, *conn_ctx;
	struct in_addr src_addr, dest_addr;
	tcp_segment segment;
	int err;

	conn_ctx = NULL;
	bind_ctx = tcp_open(&err);
	bind_ctx->peer_addr.sin_port = 5050;
	bind_ctx->my_addr.sin_port = 6060;
	bind_ctx->peer_addr.sin_addr.s_addr = inet_addr("1.1.1.1");
	bind_ctx->my_addr.sin_addr.s_addr = inet_addr("2.2.2.2");
	bind_ctx->pending_ctx_list = list_open();
	bind_ctx->backlog = 1;

	segment.header.th_sport = 5050;
	segment.header.th_dport = 6060;
	src_addr.s_addr = inet_addr("3.3.3.3");
	dest_addr.s_addr = inet_addr("4.4.4.4");

	/* Should fail: when there is no corresponding server context. */
	list_add_tail(ktcp.bind_ctx_list, bind_ctx);
	conn_ctx = (tcp_context *)tcp_create_ctx(src_addr, dest_addr, segment);
	CuAssertPtrEquals(tc, NULL, conn_ctx);

	/* Should fail: when there is a matched server context, but its pending queue is overflown. */
	bind_ctx->backlog = 0;
	bind_ctx->my_addr.sin_addr.s_addr = 0; /* INADDR_ANY */
	conn_ctx = (tcp_context *)tcp_create_ctx(src_addr, dest_addr, segment);
	CuAssertPtrEquals(tc, NULL, conn_ctx);

	/* Normal case: when bind_ctx->my_addr.sin_addr.s_addr == 0 ("0.0.0.0")
	 *   0 is same to INADDR_ANY constant defined in netinet/in.h header.
	 *   It means this socket accepts any destination address. */
	bind_ctx->backlog = 5;
	bind_ctx->my_addr.sin_addr.s_addr = 0; /* INADDR_ANY */
	conn_ctx = (tcp_context *)tcp_create_ctx(src_addr, dest_addr, segment);
	CuAssertPtrNotNull(tc, conn_ctx);
	CuAssertIntEquals(tc, dest_addr.s_addr, conn_ctx->my_addr.sin_addr.s_addr);
	CuAssertIntEquals(tc, AF_INET, conn_ctx->peer_addr.sin_family);
	CuAssertIntEquals(tc, src_addr.s_addr, conn_ctx->peer_addr.sin_addr.s_addr);
	CuAssertIntEquals(tc, segment.header.th_sport, conn_ctx->peer_addr.sin_port);
	CuAssertPtrEquals(tc, bind_ctx, conn_ctx->bind_ctx);
	CuAssertPtrEquals(tc, conn_ctx, list_get_tail(bind_ctx->pending_ctx_list));
	CuAssertPtrEquals(tc, conn_ctx, list_get_tail(ktcp.pending_ctx_list));

	/* Normal case: when dest_addr.s_addr == bind_ctx->my_addr.sin_addr.s_addr */
	bind_ctx->my_addr.sin_addr.s_addr = inet_addr("2.2.2.2");
	dest_addr.s_addr = inet_addr("2.2.2.2");
	conn_ctx = (tcp_context *)tcp_create_ctx(src_addr, dest_addr, segment);
	CuAssertPtrNotNull(tc, conn_ctx);
	CuAssertIntEquals(tc, AF_INET, conn_ctx->peer_addr.sin_family);
	CuAssertIntEquals(tc, src_addr.s_addr, conn_ctx->peer_addr.sin_addr.s_addr);
	CuAssertIntEquals(tc, segment.header.th_sport, conn_ctx->peer_addr.sin_port);
	CuAssertPtrEquals(tc, bind_ctx, conn_ctx->bind_ctx);
	CuAssertPtrEquals(tc, conn_ctx, list_get_tail(bind_ctx->pending_ctx_list));
	CuAssertPtrEquals(tc, conn_ctx, list_get_tail(ktcp.pending_ctx_list));

	list_remove_all(ktcp.bind_ctx_list);
	list_remove_all(ktcp.pending_ctx_list);
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.pending_ctx_list));

	list_remove_all(ktcp.allocated_ctx_list);
	list_close(bind_ctx->pending_ctx_list);
	free(bind_ctx);
}

void TestDispatchPending(CuTest *tc)
{
	tcp_context *svr_ctx;
	tcp_context *svrdup_ctx;
	tcp_context *bind_ctx;
	tcp_context *accept_pending_ctx;
	tcp_context *cli_ctx;
	int err;

	accept_pending_ctx = tcp_open(&err);
	accept_pending_ctx->pipe = 10;

	bind_ctx = tcp_open(&err);
	bind_ctx->accept_pending_ctx_list = list_open();
	bind_ctx->pending_ctx_list = list_open();

	svr_ctx = tcp_open(&err);
	svr_ctx->bind_ctx = bind_ctx;
	svr_ctx->my_addr.sin_family = AF_INET;
	svr_ctx->my_addr.sin_port = 5555;
	svr_ctx->my_addr.sin_addr.s_addr = inet_addr("5.5.5.5");
	svr_ctx->peer_addr.sin_family = AF_INET;
	svr_ctx->peer_addr.sin_port = 6666;
	svr_ctx->peer_addr.sin_addr.s_addr = inet_addr("6.6.6.6");
	svr_ctx->pipe = 5;

	list_add_tail(bind_ctx->pending_ctx_list, svr_ctx);

	/* svr_ctx can be freed, so make a copy */
	svrdup_ctx = tcp_open(&err);
	memcpy(svrdup_ctx, svr_ctx, sizeof(tcp_context));

	cli_ctx = tcp_open(&err);
	cli_ctx->bind_ctx = NULL;

	/* svr_ctx, cli_ctx are added to async_pending_list */
	list_add_tail(ktcp.async_pending_ctx_list, svr_ctx);
	list_add_tail(ktcp.async_pending_ctx_list, cli_ctx);
	CuAssertIntEquals(tc, 2, list_get_count(ktcp.async_pending_ctx_list));

	/* only cli_ctx must be moved from async_pending_list to conn_ctx_list */
	tcp_dispatch_pending();
	CuAssertPtrEquals(tc, cli_ctx, list_get_tail(ktcp.conn_ctx_list));
	CuAssertPtrEquals(tc, svr_ctx, list_get_tail(ktcp.async_pending_ctx_list));
	CuAssertIntEquals(tc, 1, list_get_count(ktcp.async_pending_ctx_list));
	/* ker_message check */
	CuAssertIntEquals(tc, ASYNCH_RETURN_CONNECT, ker_msg);
	CuAssertIntEquals(tc, 0, ker_status);
	CuAssertPtrEquals(tc, cli_ctx, bind_handle);

	/* svr_ctx must be move from async_pending_list to conn_ctx_list */
	list_add_tail(bind_ctx->accept_pending_ctx_list, accept_pending_ctx);
	tcp_dispatch_pending();
	/* context information check */
	CuAssertIntEquals(tc, svrdup_ctx->my_addr.sin_family, accept_pending_ctx->my_addr.sin_family);
	CuAssertIntEquals(tc, svrdup_ctx->my_addr.sin_port, accept_pending_ctx->my_addr.sin_port);
	CuAssertLonEquals(tc, svrdup_ctx->my_addr.sin_addr.s_addr, accept_pending_ctx->my_addr.sin_addr.s_addr);
	CuAssertIntEquals(tc, svrdup_ctx->peer_addr.sin_family, accept_pending_ctx->peer_addr.sin_family);
	CuAssertIntEquals(tc, svrdup_ctx->peer_addr.sin_port, accept_pending_ctx->peer_addr.sin_port);
	CuAssertLonEquals(tc, svrdup_ctx->peer_addr.sin_addr.s_addr, accept_pending_ctx->peer_addr.sin_addr.s_addr);
	/* ktcp list manipulation check */
	CuAssertIntEquals(tc, 0, list_get_count(bind_ctx->accept_pending_ctx_list));
	CuAssertPtrEquals(tc, accept_pending_ctx, list_get_tail(ktcp.conn_ctx_list));
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.async_pending_ctx_list));
	/* ker_message check */
	CuAssertIntEquals(tc, ASYNCH_RETURN_ACCEPT, ker_msg);
	CuAssertIntEquals(tc, 0, ker_status);
	CuAssertPtrEquals(tc, accept_pending_ctx, conn_handle);

	list_remove_all(ktcp.conn_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	list_remove_all(ktcp.async_pending_ctx_list);
	list_remove_all(ktcp.pending_ctx_list);
	list_remove_all(ktcp.bind_ctx_list);

	list_close(bind_ctx->accept_pending_ctx_list);
	free(bind_ctx);
	free(svrdup_ctx);
}

void TestChangeState1(CuTest *tc)
{
	tcp_context *ctx;
	tcp_segment segment;
	int err;
	
	ctx = tcp_open(&err);
	ctx->my_stream.container_list = list_open();
	segment.header.th_off = (SHS + 3) / 4;
	segment.length = MPS;

	/* SYN_RECV -> ESTABLISHED with "recv:ACK". */
	segment.header.th_flags = TH_ACK;
	ctx->state = CSTATE_SYN_RECV;
	list_add_tail(ktcp.pending_ctx_list, ctx);
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_ESTABLISHED, ctx->state);
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.pending_ctx_list));
	CuAssertPtrEquals(tc, ctx, list_get_tail(ktcp.async_pending_ctx_list));

	/* LISTEN -> SYN_RECV with "recv:SYN; send:SYN,ACK". */
	segment.header.th_flags = TH_SYN;
	ctx->state = CSTATE_LISTEN;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_SYN_RECV, ctx->state);

	/* SYN_SENT -> SYN_RECV with "recv:SYN; send:SYN,ACK". */
	ctx->state = CSTATE_SYN_SENT;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_SYN_RECV, ctx->state);

	/* SYN_SENT -> ESTABLISHED with "recv:SYN,ACK; send:ACK". */
	segment.header.th_flags = TH_SYN | TH_ACK;
	ctx->state = CSTATE_SYN_SENT;
	list_add_tail(ktcp.pending_ctx_list, ctx);
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_ESTABLISHED, ctx->state);
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.pending_ctx_list));
	CuAssertPtrEquals(tc, ctx, list_get_tail(ktcp.async_pending_ctx_list));

	list_remove_all(ktcp.async_pending_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->my_stream.container_list);
	free(ctx);
}

void TestChangeState2(CuTest *tc)
{
	tcp_context *ctx;
	tcp_segment segment;
	int err;
	
	ctx = tcp_open(&err);
	ctx->my_stream.container_list = list_open();
	segment.header.th_off = (SHS + 3) / 4;
	segment.length = MPS;

	/* CLOSING -> TIME_WAIT with "recv:ACK". */
	segment.header.th_flags = TH_ACK;
	ctx->state = CSTATE_CLOSING;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_TIME_WAIT, ctx->state);
	
	/* ESTABLISHED -> CLOSE_WAIT with "recv:FIN; send:ACK". */
	segment.header.th_flags = TH_FIN;
	ctx->state = CSTATE_ESTABLISHED;
	ctx->pipe = 5;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_CLOSE_WAIT, ctx->state);
	/* ker_message check */
	CuAssertIntEquals(tc, ASYNCH_EOF, ker_msg);
	CuAssertIntEquals(tc, 0, ker_status);
	CuAssertPtrEquals(tc, ctx, conn_handle);

	/* FIN_WAIT1 -> CLOSING with "recv:FIN; send:ACK". */
	ctx->state = CSTATE_FIN_WAIT1;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_CLOSING, ctx->state);

	/* FIN_WAIT1 -> TIME_WAIT with "recv:FIN,ACK; send:ACK". */
	segment.header.th_flags = TH_FIN | TH_ACK;
	ctx->state = CSTATE_FIN_WAIT1;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_TIME_WAIT, ctx->state);

	/* FIN_WAIT1 -> FIN_WAIT2 with "recv:ACK". */
	segment.header.th_flags = TH_ACK;
	ctx->state = CSTATE_FIN_WAIT1;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_FIN_WAIT2, ctx->state);

	/* FIN_WAIT2 -> TIME_WAIT with "recv:FIN; send:ACK". */
	segment.header.th_flags = TH_FIN;
	ctx->state = CSTATE_FIN_WAIT2;
	tcp_change_state(ctx, &segment);
	CuAssertIntEquals(tc, CSTATE_TIME_WAIT, ctx->state);

	list_close(ctx->my_stream.container_list);
	/* LAST_ACK -> CLOSED with "recv:ACK". */
	ctx->state = CSTATE_LAST_ACK;
	tcp_change_state(ctx, &segment);
	/* TODO: this context can be freed */
	/*CuAssertIntEquals(tc, CSTATE_CLOSED, ctx->state);*/

	list_remove_all(ktcp.timewait_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
}

void TestClose2(CuTest *tc)
{
	tcp_context *ctx, *bind_ctx;
	bool retValue;
	int err, i;

	ctx = tcp_open(&err);
	ctx->is_bound = true;
	ctx->my_stream.container_list = list_open();
	list_add_tail(ktcp.bind_ctx_list, ctx);

	/* state condition check */
	for(i=0; i<=CSTATE_CLOSING; i++) {
		if(i == CSTATE_SYN_RECV)
			continue;
		if(i == CSTATE_ESTABLISHED)
			continue;
		if(i == CSTATE_CLOSE_WAIT)
			continue;
		if(i == CSTATE_LISTEN)
			continue;
		if(i == CSTATE_CLOSED)
			continue;

		ctx->state = i;
		retValue = tcp_close(ctx, &err);
		CuAssertIntEquals(tc, 0, retValue);
	}
	
	/* SYN_RECV -> FIN_WAIT1 with "appl:close; send:FIN". */
	ctx->state = CSTATE_SYN_RECV;
	retValue = tcp_close(ctx, &err);
	CuAssertIntEquals(tc, 1, retValue);
	CuAssertIntEquals(tc, CSTATE_FIN_WAIT1, ctx->state);

	/* ESTABLISHED -> FIN_WAIT1 with "appl:close; send:FIN". */
	ctx->state = CSTATE_ESTABLISHED;
	retValue = tcp_close(ctx, &err);
	CuAssertIntEquals(tc, 1, retValue);
	CuAssertIntEquals(tc, CSTATE_FIN_WAIT1, ctx->state);

	/* CLOSE_WAIT -> LAST_ACK with "appl:close; send:FIN". */
	ctx->state = CSTATE_CLOSE_WAIT;
	retValue = tcp_close(ctx, &err);
	CuAssertIntEquals(tc, 1, retValue);
	CuAssertIntEquals(tc, CSTATE_LAST_ACK, ctx->state);

	list_close(ctx->my_stream.container_list);
	/* already CLOSED, also bound */
	ctx->state = CSTATE_CLOSED;
	tcp_close(ctx, &err);
	/* ker_message check */
	CuAssertIntEquals(tc, ASYNCH_CLOSE, ker_msg);
	CuAssertIntEquals(tc, 0, ker_status);
	CuAssertPtrEquals(tc, ctx, conn_handle);
	/* check: removing the context from global lists */
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.bind_ctx_list));
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.allocated_ctx_list));
}

void TestClose3(CuTest *tc)
{
	tcp_context *ctx;
	bool retValue;
	int err, i;

	ctx = tcp_open(&err);
	ctx->my_stream.container_list = list_open();
	ctx->is_bound = true;
	list_add_tail(ktcp.bind_ctx_list, ctx);

	/* state condition check */
	for(i=0; i<=CSTATE_CLOSING; i++) {
		if(i == CSTATE_SYN_RECV)
			continue;
		if(i == CSTATE_ESTABLISHED)
			continue;
		if(i == CSTATE_CLOSE_WAIT)
			continue;
		if(i == CSTATE_LISTEN)
			continue;
		if(i == CSTATE_CLOSED)
			continue;

		ctx->state = i;
		retValue = tcp_close(ctx, &err);
		CuAssertIntEquals(tc, 0, retValue);
	}
	
	/* SYN_RECV -> FIN_WAIT1 with "appl:close; send:FIN". */
	ctx->state = CSTATE_SYN_RECV;
	retValue = tcp_close(ctx, &err);
	CuAssertIntEquals(tc, 1, retValue);
	CuAssertIntEquals(tc, CSTATE_FIN_WAIT1, ctx->state);

	/* ESTABLISHED -> FIN_WAIT1 with "appl:close; send:FIN". */
	ctx->state = CSTATE_ESTABLISHED;
	retValue = tcp_close(ctx, &err);
	CuAssertIntEquals(tc, 1, retValue);
	CuAssertIntEquals(tc, CSTATE_FIN_WAIT1, ctx->state);

	/* CLOSE_WAIT -> LAST_ACK with "appl:close; send:FIN". */
	ctx->state = CSTATE_CLOSE_WAIT;
	retValue = tcp_close(ctx, &err);
	CuAssertIntEquals(tc, 1, retValue);
	CuAssertIntEquals(tc, CSTATE_LAST_ACK, ctx->state);

	list_close(ctx->my_stream.container_list);
	/* already CLOSED */
	ctx->state = CSTATE_CLOSED;
	tcp_close(ctx, &err);
	/* ker_message check */
	CuAssertIntEquals(tc, ASYNCH_CLOSE, ker_msg);
	CuAssertIntEquals(tc, 0, ker_status);
	CuAssertPtrEquals(tc, ctx, conn_handle);
	/* check: removing the context from global lists */
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.bind_ctx_list));
	CuAssertIntEquals(tc, 0, list_get_count(ktcp.allocated_ctx_list));
}

void TestCleanupTimewaitCtx(CuTest *tc)
{
	tcp_context *ctx, *timeout_ctx;
	list_position pos;
	int now, err;

	ctx = tcp_open(&err);
	ctx->timeout = 5000;
	ctx->state = CSTATE_TIME_WAIT;
	list_add_tail(ktcp.timewait_ctx_list, ctx);

	timeout_ctx = tcp_open(&err);
	timeout_ctx->timeout = 1000;
	timeout_ctx->state = CSTATE_TIME_WAIT;
	list_add_tail(ktcp.timewait_ctx_list, timeout_ctx);

	tcp_cleanup_timewait_ctx(3000);
	/* cleanup not ctx, but timeout_ctx */
	CuAssertIntEquals(tc, 1, list_get_count(ktcp.timewait_ctx_list));
	CuAssertPtrEquals(tc, ctx, list_get_tail(ktcp.timewait_ctx_list));
	/* timeout_ctx is freed in the ktcp code! */
	/*CuAssertIntEquals(tc, CSTATE_CLOSED, timeout_ctx->state);*/

	list_remove_all(ktcp.allocated_ctx_list);
	list_remove_all(ktcp.timewait_ctx_list);
	free(ctx);
}

void TestAddToMyStream(CuTest *tc)
{
	tcp_context *ctx;
	tcp_container *container;
	u_char flags;
	tcp_seq old_seq_num;
	char data[MPS];
	size_t data_length;
	int err, i;

	ctx = tcp_open(&err);
	ctx->my_addr.sin_port = 5050;
	ctx->peer_addr.sin_port = 6060;
	ctx->my_stream.container_list = list_open();

	old_seq_num = 0;
	ctx->my_stream.seq_num = old_seq_num;

	/* test with SYN segment */
	tcp_add_to_my_stream(ctx, TH_SYN, NULL, 0);
	CuAssertIntEquals(tc, 1, list_get_count(ctx->my_stream.container_list));
	container = list_get_tail(ctx->my_stream.container_list);
	CuAssertIntEquals(tc, TH_SYN, container->flags);
	CuAssertIntEquals(tc, 0, container->data_length);
	CuAssertIntEquals(tc, old_seq_num, container->seq_num);
	CuAssertIntEquals(tc, container->seq_num + 1, ctx->my_stream.seq_num);

	old_seq_num = ctx->my_stream.seq_num;

	/* test with FIN segment */
	tcp_add_to_my_stream(ctx, TH_FIN, NULL, 0);
	CuAssertIntEquals(tc, 2, list_get_count(ctx->my_stream.container_list));
	container = list_get_tail(ctx->my_stream.container_list);
	CuAssertIntEquals(tc, TH_FIN, container->flags);
	CuAssertIntEquals(tc, 0, container->data_length);
	CuAssertIntEquals(tc, old_seq_num, container->seq_num);
	CuAssertIntEquals(tc, container->seq_num + 1, ctx->my_stream.seq_num);

	old_seq_num = ctx->my_stream.seq_num;

	/* test with normal data segment with TH_ACK */
	flags = TH_ACK;
	memset(data, 1, MPS);
	data_length = sizeof(data);
	tcp_add_to_my_stream(ctx, flags, data, data_length);
	CuAssertIntEquals(tc, 3, list_get_count(ctx->my_stream.container_list));
	container = list_get_tail(ctx->my_stream.container_list);
	CuAssertIntEquals(tc, flags, container->flags);
	CuAssertIntEquals(tc, data_length, container->data_length);
	CuAssertIntEquals(tc, old_seq_num, container->seq_num);
	CuAssertIntEquals(tc, container->seq_num + data_length, ctx->my_stream.seq_num);

	for(i=0; i<data_length; i++)
		CuAssertIntEquals(tc, data[i], container->data[i]);

	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->my_stream.container_list);
	free(ctx);
}

void TestSendStream3(CuTest *tc)
{
	tcp_context *pending_ctx, *conn_ctx;
	tcp_container *syn_container;
	tcp_container *container[10];
	int err, i;
	
	/* create handshaking context and insert into pending list */
	pending_ctx = tcp_open(&err);
	pending_ctx->my_stream.ack_num = 0;
	pending_ctx->my_stream.win = 100;
	pending_ctx->my_stream.container_list = list_open();
	list_add_tail(ktcp.pending_ctx_list, pending_ctx);

	/* insert SYN container into handshaking context's send buffer */
	syn_container = (tcp_container *)malloc(sizeof(tcp_container));
	memset(syn_container, 0, sizeof(tcp_container));
	syn_container->seq_num = 0;
	syn_container->flags = TH_SYN;
	syn_container->data_length = 0;
	memset(syn_container->data, 0, MPS);
	list_add_tail(pending_ctx->my_stream.container_list, syn_container);

	trans_segment = 0;
	tcp_send_stream();
	CuAssertIntEquals(tc, 1, trans_segment);
	CuAssertIntEquals(tc, false, syn_container->last_sent == 0);
	CuAssertIntEquals(tc, false, syn_container->timeout == 0);
	CuAssertIntEquals(tc, 1, syn_container->trial);

	/* create established context and insert into conn list */
	conn_ctx = tcp_open(&err);
	conn_ctx->my_stream.ack_num = 1000;
	conn_ctx->my_stream.win = 3072;
	conn_ctx->my_stream.container_list = list_open();
	list_add_tail(ktcp.conn_ctx_list, conn_ctx);

	/* insert data containers into established context's send buffer */
	for(i=0; i<10; i++) {
		container[i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[i], 0, sizeof(tcp_container));
		container[i]->seq_num = 1000 + MPS * i;
		container[i]->flags = TH_ACK;
		container[i]->data_length = MPS;
		memset(container[i]->data, 1, MPS);
		list_add_tail(conn_ctx->my_stream.container_list, container[i]);
	}

	trans_segment = 0;
	tcp_send_stream();
	/* first 6 data containers have to be transmitted */
	CuAssertIntEquals(tc, 6, trans_segment);
	for(i=0; i<trans_segment; i++) {
		CuAssertIntEquals(tc, false, container[i]->last_sent == 0);
		CuAssertIntEquals(tc, false, container[i]->timeout == 0);
		CuAssertIntEquals(tc, 1, container[i]->trial);
	}

	for(i=trans_segment; i<10; i++) {
		CuAssertIntEquals(tc, 0, container[i]->last_sent);
		CuAssertIntEquals(tc, 0, container[i]->timeout);
		CuAssertIntEquals(tc, 0, container[i]->trial);
	}

	/* cannot transmit last 4 data containers (out of send window) */
	list_remove_all(ktcp.pending_ctx_list);
	list_remove_all(ktcp.conn_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	list_close(pending_ctx->my_stream.container_list);
	list_close(conn_ctx->my_stream.container_list);
	free(syn_container);
	for(i=0; i<10; i++)
		free(container[i]);
	free(pending_ctx);
	free(conn_ctx);
}

void TestSendStream4(CuTest *tc)
{
	tcp_context *pending_ctx, *conn_ctx;
	tcp_container *syn_container;
	tcp_container *container[10];
	int err, i;
	
	/* create handshaking context and insert into pending list */
	pending_ctx = tcp_open(&err);
	pending_ctx->my_stream.ack_num = 0;
	pending_ctx->my_stream.win = 100;
	pending_ctx->my_stream.container_list = list_open();
	pending_ctx->snd_cwnd = MSS;
	list_add_tail(ktcp.pending_ctx_list, pending_ctx);

	/* insert SYN container into handshaking context's send buffer */
	syn_container = (tcp_container *)malloc(sizeof(tcp_container));
	memset(syn_container, 0, sizeof(tcp_container));
	syn_container->seq_num = 0;
	syn_container->flags = TH_SYN;
	syn_container->data_length = 0;
	memset(syn_container->data, 0, MPS);
	list_add_tail(pending_ctx->my_stream.container_list, syn_container);

	trans_segment = 0;
	tcp_send_stream();
	CuAssertIntEquals(tc, 1, trans_segment);
	CuAssertIntEquals(tc, false, syn_container->last_sent == 0);
	CuAssertIntEquals(tc, false, syn_container->timeout == 0);
	CuAssertIntEquals(tc, 1, syn_container->trial);

	/* create established context and insert into conn list */
	conn_ctx = tcp_open(&err);
	conn_ctx->my_stream.ack_num = 1000;
	conn_ctx->my_stream.win = 3072;
	conn_ctx->snd_cwnd = 2072;
	conn_ctx->my_stream.container_list = list_open();
	list_add_tail(ktcp.conn_ctx_list, conn_ctx);

	/* insert data containers into established context's send buffer */
	for(i=0; i<10; i++) {
		container[i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[i], 0, sizeof(tcp_container));
		container[i]->seq_num = 1000 + MPS * i;
		container[i]->flags = TH_ACK;
		container[i]->data_length = MPS;
		memset(container[i]->data, 1, MPS);
		list_add_tail(conn_ctx->my_stream.container_list, container[i]);
	}

	trans_segment = 0;
	tcp_send_stream();
	/* first 5 data containers have to be transmitted */
	CuAssertIntEquals(tc, 5, trans_segment);
	for(i=0; i<trans_segment; i++) {
		CuAssertIntEquals(tc, false, container[i]->last_sent == 0);
		CuAssertIntEquals(tc, false, container[i]->timeout == 0);
		CuAssertIntEquals(tc, 1, container[i]->trial);
	}

	for(i=trans_segment; i<10; i++) {
		CuAssertIntEquals(tc, 0, container[i]->last_sent);
		CuAssertIntEquals(tc, 0, container[i]->timeout);
		CuAssertIntEquals(tc, 0, container[i]->trial);
	}

	/* cannot transmit last 5 data containers (out of send window) */
	list_remove_all(ktcp.pending_ctx_list);
	list_remove_all(ktcp.conn_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	list_close(pending_ctx->my_stream.container_list);
	list_close(conn_ctx->my_stream.container_list);
	free(syn_container);
	for(i=0; i<10; i++)
		free(container[i]);
	free(pending_ctx);
	free(conn_ctx);
}

void TestAcceptPeerACK3(CuTest *tc)
{
	tcp_context *ctx;
	tcp_segment segment;
	tcp_container *container[10];
	int err, i;

	ctx = tcp_open(&err);
	ctx->my_stream.seq_num = 1000 + MPS * 10;
	ctx->my_stream.ack_num = 1000;
	ctx->my_stream.container_list = list_open();

	for(i=0; i<10; i++) {
		container[i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[i], 0, sizeof(tcp_container));
		container[i]->seq_num = 1000 + MPS * i;
		container[i]->flags = TH_ACK;
		container[i]->data_length = MPS;
		memset(container[i]->data, 1, MPS);
		list_add_tail(ctx->my_stream.container_list, container[i]);
	}

	/* cumulative ACK test */
	segment.header.th_flags = TH_ACK;
	segment.header.th_ack = htonl(1000 + MPS * 5);
	tcp_accept_peer_ack(ctx, &segment);
	CuAssertIntEquals(tc, 5, list_get_count(ctx->my_stream.container_list));
	CuAssertIntEquals(tc, 1000 + MPS * 5, ((tcp_container *)list_get_head(ctx->my_stream.container_list))->seq_num);
	CuAssertIntEquals(tc, 1000 + MPS * 5, ctx->my_stream.ack_num);

	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->my_stream.container_list);
	for(i=5; i<10; i++)
		free(container[i]);
	free(ctx);
}

void TestAcceptPeerACK4(CuTest *tc)
{
	tcp_context *ctx;
	tcp_segment segment;
	tcp_container *container[10];
	tcp_seq old_ack_num;
	int old_cwnd;
	int err, i;

	ctx = tcp_open(&err);
	ctx->my_stream.seq_num = 1000 + MPS * 10;
	ctx->my_stream.ack_num = 1000;
	ctx->my_stream.win = 3072;
	ctx->snd_cwnd = 2072;
	ctx->snd_ssthresh = 3000;
	ctx->t_dupacks = 2;
	old_ack_num = ctx->my_stream.ack_num;
	old_cwnd = ctx->snd_cwnd;
	ctx->my_stream.container_list = list_open();

	for(i=0; i<10; i++) {
		container[i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[i], 0, sizeof(tcp_container));
		container[i]->seq_num = 1000 + MPS * i;
		container[i]->flags = TH_ACK;
		container[i]->data_length = MPS;
		memset(container[i]->data, 1, MPS);
		list_add_tail(ctx->my_stream.container_list, container[i]);
	}

	/* check: increase the congestion window ( < threshold ) */
	segment.header.th_flags = TH_ACK;
	segment.header.th_ack = htonl(1000 + MPS * 5);
	tcp_accept_peer_ack(ctx, &segment);
	CuAssertIntEquals(tc, 1000 + MPS * 5, ctx->my_stream.ack_num);
	CuAssertIntEquals(tc, old_cwnd + ctx->my_stream.ack_num - old_ack_num, ctx->snd_cwnd);
	CuAssertIntEquals(tc, 0, ctx->t_dupacks);

	old_ack_num = ctx->my_stream.ack_num;
	old_cwnd = ctx->snd_cwnd;

	/* check: increase the congestion window ( > threshold ) */
	segment.header.th_ack = htonl(1000 + MPS * 8);
	tcp_accept_peer_ack(ctx, &segment);
	CuAssertIntEquals(tc, 1000 + MPS * 8, ctx->my_stream.ack_num);
	CuAssertIntEquals(tc, old_cwnd + (ctx->my_stream.ack_num - old_ack_num) * (ctx->my_stream.ack_num - old_ack_num) / old_cwnd, ctx->snd_cwnd);
	CuAssertIntEquals(tc, 0, ctx->t_dupacks);

	old_ack_num = ctx->my_stream.ack_num;
	old_cwnd = ctx->snd_cwnd;
	ctx->t_dupacks = 2;

	/* check: decrease the congestion window (duplicated ACK) */
	segment.header.th_win = 3072;
	tcp_accept_peer_ack(ctx, &segment);
	CuAssertIntEquals(tc, 1000 + MPS * 8, ctx->my_stream.ack_num);
	CuAssertIntEquals(tc, MAX(old_cwnd/(2*MSS), 2) * MSS, ctx->snd_cwnd);
	CuAssertIntEquals(tc, MAX(old_cwnd/(2*MSS), 2) * MSS, ctx->snd_ssthresh);

	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->my_stream.container_list);
	for(i=8; i<10; i++)
		free(container[i]);
	free(ctx);
}

void TestAcceptPeerSYN(CuTest *tc)
{
	tcp_context *ctx;
	tcp_segment segment;
	int err, i;

	ctx = tcp_open(&err);

	segment.header.th_win = htons(3072);
	segment.header.th_seq = htonl(0);
	segment.header.th_flags = TH_SYN;

	/* state condition check */
	for(i=0; i<=CSTATE_CLOSING; i++) {
		if(i == CSTATE_LISTEN)
			continue;
		if(i == CSTATE_SYN_SENT)
			continue;
		ctx->state = i;
		tcp_accept_peer_syn(ctx, &segment);
		CuAssertPtrEquals(tc, NULL, ctx->peer_stream.container_list);
	}

	ctx->state = CSTATE_LISTEN;
	tcp_accept_peer_syn(ctx, &segment);
	CuAssertIntEquals(tc, ntohs(segment.header.th_win), ctx->my_stream.win);
	CuAssertIntEquals(tc, ntohl(segment.header.th_seq) + 1, ctx->peer_stream.ack_num);
	CuAssertPtrNotNull(tc, ctx->peer_stream.container_list);

	list_close(ctx->peer_stream.container_list);
	segment.header.th_win = htons(3073);
	segment.header.th_seq = htonl(1);

	ctx->state = CSTATE_SYN_SENT;
	tcp_accept_peer_syn(ctx, &segment);
	CuAssertIntEquals(tc, ntohs(segment.header.th_win), ctx->my_stream.win);
	CuAssertIntEquals(tc, ntohl(segment.header.th_seq) + 1, ctx->peer_stream.ack_num);
	CuAssertPtrNotNull(tc, ctx->peer_stream.container_list);

	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->peer_stream.container_list);
	free(ctx);
}

void TestAcceptPeerFIN(CuTest *tc)
{
	tcp_context *ctx;
	tcp_segment segment;
	int err, i;

	ctx = tcp_open(&err);
	ctx->peer_stream.ack_num = 5000;

	segment.header.th_flags = TH_FIN;

	/* state condition check */
	for(i=0; i<=CSTATE_CLOSING; i++) {
		if(i == CSTATE_ESTABLISHED)
			continue;
		if(i == CSTATE_FIN_WAIT1)
			continue;
		if(i == CSTATE_FIN_WAIT2)
			continue;
		ctx->state = i;
		tcp_accept_peer_fin(ctx, &segment);
		CuAssertIntEquals(tc, 5000, ctx->peer_stream.ack_num);
	}

	ctx->state = CSTATE_ESTABLISHED;
	tcp_accept_peer_fin(ctx, &segment);
	CuAssertIntEquals(tc, 5001, ctx->peer_stream.ack_num);

	ctx->state = CSTATE_FIN_WAIT1;
	tcp_accept_peer_fin(ctx, &segment);
	CuAssertIntEquals(tc, 5002, ctx->peer_stream.ack_num);

	ctx->state = CSTATE_FIN_WAIT2;
	tcp_accept_peer_fin(ctx, &segment);
	CuAssertIntEquals(tc, 5003, ctx->peer_stream.ack_num);

	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);
}

void TestAddToPeerStream(CuTest *tc)
{
	tcp_context *ctx;
	tcp_segment segment;
	tcp_container *container;
	tcp_seq data_length;
	tcp_seq old_ack_num;
	int err, i;

	ctx = tcp_open(&err);
	ctx->peer_stream.ack_num = 1000;
	ctx->peer_stream.container_list = list_open();

	/* segment in order */
	segment.header.th_seq = htonl(1000);
	segment.header.th_off = (SHS + 3) / 4;
	segment.length = SHS + MPS;
	data_length = segment.length - (segment.header.th_off * 4);
	memset(segment.data, 1, MPS);

	tcp_add_to_peer_stream(ctx, &segment);
	CuAssertIntEquals(tc, htonl(segment.header.th_seq) + data_length, ctx->peer_stream.ack_num);
	CuAssertIntEquals(tc, 1, list_get_count(ctx->peer_stream.container_list));
	container = list_get_head(ctx->peer_stream.container_list);
	CuAssertIntEquals(tc, htonl(segment.header.th_seq), container->seq_num);
	CuAssertIntEquals(tc, data_length, container->data_length);
	for(i=0; i<data_length; i++)
		CuAssertIntEquals(tc, segment.data[i], container->data[i]);

	/* segment out of order */
	segment.header.th_seq = htonl(2000);
	memset(segment.data, 2, MPS);
	old_ack_num = ctx->peer_stream.ack_num;

	tcp_add_to_peer_stream(ctx, &segment);
	CuAssertIntEquals(tc, old_ack_num, ctx->peer_stream.ack_num);
	CuAssertIntEquals(tc, 1, list_get_count(ctx->peer_stream.container_list));
	CuAssertPtrEquals(tc, container, list_get_head(ctx->peer_stream.container_list));

	list_close(ctx->peer_stream.container_list);
	list_remove_all(ktcp.allocated_ctx_list);
	free(ctx);
}

void TestRecvStream(CuTest *tc)
{
	tcp_context *ctx, *ctx2;
	tcp_container *container[20];
	int err, i;

	ctx = tcp_open(&err);
	ctx->peer_stream.ack_num = 1000 + MPS * 10;
	ctx->peer_stream.container_list = list_open();
	list_add_tail(ktcp.conn_ctx_list, ctx);
	
	ctx2 = tcp_open(&err);
	ctx2->peer_stream.ack_num = 2000 + MPS * 10;
	ctx2->peer_stream.container_list = list_open();
	list_add_tail(ktcp.conn_ctx_list, ctx2);

	/* insert data containers into context's recv buffer */
	for(i=0; i<10; i++) {
		container[i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[i], 0, sizeof(tcp_container));
		container[i]->seq_num = 1000 + MPS * i;
		container[i]->flags = TH_ACK;
		container[i]->data_length = MPS;
		memset(container[i]->data, 1, MPS);
		list_add_tail(ctx->peer_stream.container_list, container[i]);
	}

	for(i=0; i<10; i++) {
		container[10+i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[10+i], 0, sizeof(tcp_container));
		container[10+i]->seq_num = 2000 + MPS * i;
		container[10+i]->flags = TH_ACK;
		container[10+i]->data_length = MPS;
		memset(container[10+i]->data, 1, MPS);
		list_add_tail(ctx2->peer_stream.container_list, container[10+i]);
	}

	tcp_recv_stream();
	CuAssertIntEquals(tc, 0, list_get_count(ctx->peer_stream.container_list));
	CuAssertIntEquals(tc, 0, list_get_count(ctx2->peer_stream.container_list));

	list_remove_all(ktcp.conn_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->peer_stream.container_list);
	list_close(ctx2->peer_stream.container_list);
	free(ctx);
	free(ctx2);
}

void TestRetransmit3(CuTest *tc)
{
	tcp_context *ctx;
	tcp_container *container[10];
	int err, i;
	
	ctx = tcp_open(&err);
	ctx->my_stream.ack_num = 1000;
	ctx->my_stream.win = 3072;
	ctx->my_stream.container_list = list_open();

	/* insert data containers into context's send buffer */
	for(i=0; i<10; i++) {
		container[i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[i], 0, sizeof(tcp_container));
		container[i]->seq_num = 1000 + MPS * i;
		container[i]->flags = TH_ACK;
		container[i]->timeout = i+1;
		container[i]->data_length = MPS;
		memset(container[i]->data, 1, MPS);
		list_add_tail(ctx->my_stream.container_list, container[i]);
	}

	trans_segment = 0;
	tcp_retransmit(ctx);
	/* first 6 data containers have to be retransmitted */
	CuAssertIntEquals(tc, 6, trans_segment);
	for(i=0; i<trans_segment; i++) {
		CuAssertIntEquals(tc, false, container[i]->last_sent == 0);
		CuAssertIntEquals(tc, false, container[i]->timeout == 0);
		CuAssertIntEquals(tc, 1, container[i]->trial);
	}

	for(i=trans_segment; i<10; i++) {
		CuAssertIntEquals(tc, 0, container[i]->last_sent);
		CuAssertIntEquals(tc, 0, container[i]->timeout);
		CuAssertIntEquals(tc, 0, container[i]->trial);
	}

	/* cannot retransmit last 4 data containers (out of send window) */
	list_remove_all(ktcp.conn_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->my_stream.container_list);
	for(i=0; i<10; i++)
		free(container[i]);
	free(ctx);
}

void TestRetransmit4(CuTest *tc)
{
	tcp_context *ctx;
	tcp_container *container[10];
	int old_cwnd;
	int err, i;
	
	ctx = tcp_open(&err);
	ctx->my_stream.ack_num = 1000;
	ctx->my_stream.win = 3072;
	ctx->my_stream.container_list = list_open();
	ctx->snd_cwnd = 2072;

	/* insert data containers into context's send buffer */
	for(i=0; i<10; i++) {
		container[i] = (tcp_container *)malloc(sizeof(tcp_container));
		memset(container[i], 0, sizeof(tcp_container));
		container[i]->seq_num = 1000 + MPS * i;
		container[i]->flags = TH_ACK;
		container[i]->timeout = i+1;
		container[i]->data_length = MPS;
		memset(container[i]->data, 1, MPS);
		list_add_tail(ctx->my_stream.container_list, container[i]);
	}

	old_cwnd = ctx->snd_cwnd;
	trans_segment = 0;
	tcp_retransmit(ctx);

	/* congestion window size is decreased */
	CuAssertIntEquals(tc, MSS, ctx->snd_cwnd);
	CuAssertIntEquals(tc, MAX((old_cwnd)/(2*MSS), 2) * MSS, ctx->snd_ssthresh);

	/* first 2 data containers have to be retransmitted */
	CuAssertIntEquals(tc, 2, trans_segment);
	for(i=0; i<trans_segment; i++) {
		CuAssertIntEquals(tc, false, container[i]->last_sent == 0);
		CuAssertIntEquals(tc, false, container[i]->timeout == 0);
		CuAssertIntEquals(tc, 1, container[i]->trial);
	}

	for(i=trans_segment; i<10; i++) {
		CuAssertIntEquals(tc, 0, container[i]->last_sent);
		CuAssertIntEquals(tc, 0, container[i]->timeout);
		CuAssertIntEquals(tc, 0, container[i]->trial);
	}

	/* cannot retransmit last 5 data containers (out of send window) */
	list_remove_all(ktcp.conn_ctx_list);
	list_remove_all(ktcp.allocated_ctx_list);
	list_close(ctx->my_stream.container_list);
	for(i=0; i<10; i++)
		free(container[i]);
	free(ctx);
}

void initTest()
{
	segment = (tcp_segment *)malloc(sizeof(tcp_segment));
	trans_segment = 0;
	tcp_startup();
}

int ker_message(char msg_id, int status, tcp_context *tcp_bind_handle, tcp_context *tcp_conn_handle)
{
	ker_msg = msg_id;
	ker_status = status;
	bind_handle = tcp_bind_handle;
	conn_handle = tcp_conn_handle;
	
	return 0;
}

int ip_output(struct in_addr src_addr, struct in_addr dest_addr, tcp_segment *data, size_t data_size, route *ro)
{
	memcpy(segment, data, sizeof(tcp_segment));
	trans_segment++;
	return (int)data_size;
}

uint32_t ip_host_address(struct in_addr in)
{
	return 0x0100007F;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "iniparser.h"

#include "route.h"
#include "datalink.h"
#include "krip.h"
#include "log.h"
#include "linked_list.h"
#include "misc.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

/* is krip enabled */
static int _enabled;
/* the last advertisement time */
static unsigned int _update_time;

/* advertisement interval */
static unsigned int _update_interval;
/* timeout */
static unsigned int _timeout;

static list _rip_info_list;
static list _neighbor_info_list;

/* the udp socket for RIP */
static int _sock;

static void krip_send_request(neighbor_info *ni);
static void krip_send_response(neighbor_info *ni, int send_changed_info_only);

static u_int krip_get_mtime();

static void krip_dispatch_timeout();
static void krip_dispatch_in();
static void krip_dispatch_out();

#define MIN(x,y)  ((x) <= (y) ? (x) : (y))


int krip_init(dictionary *conf)
{
	char *svrname;
	char *vip, *ip, *port, *if_name;
	char *p;
	char *c;
	char file[1024], buf[512];
	FILE *fp;
	struct sockaddr_in sin;
	int listen;

	/* parse the configuration file */
	svrname = iniparser_getstring(conf, "KENS:server_name", "KENS");

	sprintf(file, "%s_krip", svrname);
	fp = fopen(file, "r");
	if (fp == NULL) {
		_enabled = 0;
		return 0;
	}

	_update_time = krip_get_mtime();

	c = iniparser_getstring(conf,"KENS:krip_update_interval","3000");
	_update_interval = atoi(c);

	c = iniparser_getstring(conf,"KENS:krip_timeout","7000");
	_timeout = atoi(c);

	_rip_info_list = list_open();
	_neighbor_info_list = list_open();

	if ((_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("krip");
		return -1;
	}

	_enabled = 1;

	/* configuration example:
	 * listen 127.0.0.1:9501
	 * 10.1.0.1 seth0 127.0.0.1:9502
	 * 10.1.1.1 seth1 127.0.0.1:9503
	 */

	while (fgets(buf, 512, fp)) {
		p = strchr(buf, '#');
		if (p != NULL) *p = '\0';
		if (buf[strlen(buf) - 1] == '\n') buf[strlen(buf) - 1] = '\0';
		
		p = buf;
		p = eat_ws(p);
		if (p == NULL) continue;

		if (strncmp(buf, "listen", 6) == 0) {
			listen = 1;

			p += 6;
			p = eat_ws(p);
		}
		else {
			listen = 0;
			
			vip = p;
			p = eat_ipaddr(vip);
			*p++ = '\0';
			p = eat_ws(p);

			if_name = p;
			p = eat_alphanum(if_name);
			*p++ = '\0';
			p = eat_ws(p);
		}

		ip = p;
		p = eat_ipaddr(ip);
		*p++ = '\0';
		port = p;
		p = eat_digit(port);

		if (listen)
		{
			L_ROUTE("krip: bind to %s:%s", ip, port);
			sin.sin_family = AF_INET;
			inet_aton(ip, &sin.sin_addr);
			sin.sin_port = htons((in_port_t)atoi(port));
			if (bind(_sock, (struct sockaddr *)&sin, sizeof(sin))) {
				perror("krip");
				return -1;
			}
		}
		else
		{
			L_ROUTE("krip: register neighbor %s(%s:%s)", vip, ip, port);
			neighbor_info *ni = (neighbor_info *)malloc(sizeof(neighbor_info));
			inet_aton(vip, &ni->virtual_addr);
			ni->krip_addr.sin_family = AF_INET;
			inet_aton(ip, &ni->krip_addr.sin_addr);
			ni->krip_addr.sin_port = htons((in_port_t)atoi(port));
			ni->ifp = ifunit(if_name);
			if (!ni->ifp) {
				L_ROUTE("krip: invalid interface name: %s", if_name);
				free(ni);
				continue;
			}

			list_add_tail(_neighbor_info_list, ni);
		}
	}

	fclose(fp);

	/* fetch routing table entries */
	list rte_list = rt_query();
	list_position pos;
	for (pos = list_get_head_position(rte_list);
			pos; pos = list_get_next_position(pos)) {
		rtentry *rte = list_get_at(pos);
		for (; rte; rte = (rtentry *)((radix_node *)rte)->rn_dupedkey) {
			if (((radix_node *)rte)->rn_mask == NULL)
				continue;
			if (rte->dst.s_addr == 0x00000000) {
				L_ROUTE("krip: default gw %s", inet_ntoa(rte->gw));
			}
			else if (rte->dst.s_addr == inet_addr("127.0.0.1")) {
			}
			else {
				L_ROUTE("krip: dst %s", inet_ntoa(rte->dst));
				L_ROUTE("krip: mask %s", inet_ntoa(rte->mask));
				L_ROUTE("krip: gw %s", inet_ntoa(rte->gw));

				rip_info *ri = (rip_info *)malloc(sizeof(rip_info));
				ri->assoc_rte = rte;
				ri->metric = 1;
				ri->change_flag = 1;
				ri->timeout = 0;
				ri->from = NULL;
				list_add_tail(_rip_info_list, ri);
			}
		}
	}

	/* send initial request packets */
	pos = list_get_head_position(_neighbor_info_list);
	for (; pos; pos = list_get_next_position(pos)) {
		neighbor_info *ni = list_get_at(pos);
		krip_send_request(ni);
	}

	return 0;
}

int krip_shutdown(void)
{
	list_position pos;

	if (!_enabled)
		return 0;

	for (pos = list_get_head_position(_rip_info_list);
			pos; pos = list_get_next_position(pos))
		free(list_get_at(pos));
	list_close(_rip_info_list);

	for (pos = list_get_head_position(_neighbor_info_list);
			pos; pos = list_get_next_position(pos))
		free(list_get_at(pos));
	list_close(_neighbor_info_list);

	close(_sock);

	return 0;
}

int krip_dispatch(void)
{
	if (!_enabled)
		return 0;

	krip_dispatch_timeout();
	krip_dispatch_in();
	krip_dispatch_out();
}

/* handle timeouts */
static void krip_dispatch_timeout()
{
	/* TODO: implement */
}

/* handle incoming packets */
static void krip_dispatch_in()
{
	fd_set fds;
	struct timeval timeout;
	int rc;
	int i;
	list_position pos;

	FD_ZERO(&fds);
	FD_SET(_sock, &fds);
	timeout.tv_sec = 0;
	timeout.tv_usec = 0;

	while ((rc = select(_sock + 1, &fds, NULL, NULL, &timeout)) > 0) {
		rip_buf buf;
		size_t len = RIP_PACKET_MAXSIZ;
		struct sockaddr_in from;
		size_t fromlen = sizeof(from);
		len = recvfrom(_sock, buf.buf, len, 0, (struct sockaddr *)&from, &fromlen);

		/* find the sender */
		neighbor_info *ni = NULL;
		pos = list_get_head_position(_neighbor_info_list);
		for (; pos; pos = list_get_next_position(pos)) {
			ni = list_get_at(pos);
			if (from.sin_addr.s_addr == ni->krip_addr.sin_addr.s_addr &&
					from.sin_port == ni->krip_addr.sin_port)
				break;
		}

		if (!ni) {
			L_ROUTE("krip: unknown neighbor %s:%d", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
			continue;
		}

		if (!ni->ifp->if_enabled) {
			L_ROUTE("krip: ignored response from %s", inet_ntoa(ni->virtual_addr));
			continue;
		}

		L_ROUTE("krip: response from %s", inet_ntoa(ni->virtual_addr));

		/* TODO: implement */

		/* to modify existing routing table entry:
		 * ri->assoc_rte->gw.s_addr = ni->virtual_addr.s_addr;
		 * ri->assoc_rte->rt_ifp = ni->ifp;
		 * ri->metric = new_metric;
		 * ri->change_flag = 1;
		 * ri->from = ni->ifp;
		 *
		 * ip_invalidate_forward_rt_cache(); */

		/* to insert new routing table entry:
		 * rtentry *rte = (rtentry *)malloc(sizeof(rtentry));
		 * rte->dst = rtep->prefix;
		 * rte->mask = rtep->mask;
		 * rte->gw = ni->virtual_addr;
		 * rte->rt_ifp = ni->ifp;
		 *
		 * if (rt_insert(rte)) {
		 *     L_ROUTE("krip: failed to insert new route");
		 *     free(rte);
		 *     break;
		 * }
		 *
		 * ri = (rip_info *)malloc(sizeof(rip_info));
		 * ri->assoc_rte = rte;
		 * ri->metric = new_metric;
		 * ri->change_flag = 1;
		 * ri->timeout = now + _timeout;
		 * ri->from = ni->ifp;
		 * list_add_tail(_rip_info_list, ri);
		 *
		 * ip_invalidate_forward_rt_cache(); */
	}
	
	if (rc < 0)
		perror("krip");
}

/* send packets */
static void krip_dispatch_out()
{
	/* TODO: implement */
}

/* send a RIP request packet to a neighbor */
static void krip_send_request(neighbor_info *ni)
{
	rip_buf buf;
	memset(&buf, 0, sizeof(buf));
	
	buf.rip_packet.command = RIP_REQUEST;
	buf.rip_packet.version = RIPv2;

	if (sendto(_sock, buf.buf, RIP_HEADER_SIZE, 0,
			(struct sockaddr *)&ni->krip_addr,
			sizeof(struct sockaddr_in)) == -1) {
		perror("krip");
	}
}

/* send a RIP response packet to a neighbor */
static void krip_send_response(neighbor_info *ni, int send_changed_info_only)
{
	/* TODO: implement */
}

static u_int krip_get_mtime()
{
    /* taken from ktcp.c */
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

int krip_get_update_interval()
{
	return _update_interval;
}

int krip_set_update_interval(int interval)
{
	_update_interval = interval;
	return 0;
}

int krip_get_timeout()
{
	return _timeout;
}

int krip_set_timeout(int timeout)
{
	_timeout = timeout;
	return 0;
}


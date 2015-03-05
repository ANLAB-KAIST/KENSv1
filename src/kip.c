#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <signal.h>

#include "datalink.h"
#include "kip.h"
#include "ktcp.h"
#include "log.h"

#include "kmgmt.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

/* Maximum Payload size is a full size KTCP packet */
#define MAX_PAYLOAD_SIZE	20+536
#define	KIP_HEADER_SIZE		20
#define MAX_PACKET_SIZE		(KIP_HEADER_SIZE+MAX_PAYLOAD_SIZE)

#define MAX_NUM_SOCKFDS		4

/* Maximum Transmission Unit */
#define MTU	576

static unsigned short ip_id;

/**
 * initialize KIP layer. loading routing table and firewall configuration
 * should be done in this function. This function is called before KENS
 * enters its main dispatch loop.
 * @param conf a pointer to KENS configuration file hash structure
 * @return 0 when success, others when errors
 */
int ip_init(dictionary *conf)
{
	ip_id ^= (unsigned char)((getpid()*getppid()*time(NULL)) & 0xffff);

	rt_init(conf);

	return 0;
}

/**
 * shutdown and free whole resources which were allocated at ip_init() or
 * during KENS runtime, especially resources related to routing table and 
 * firewall. This function is called after KENS receive a termination signal
 * from user.
 * @return 0 when success, others when errors
 */
int ip_shutdown(void)
{
	rt_cleanup();
	return 0;
}

/** 
 * This fuction reduces the ttl of the fragment packets in reassembly list. 
 * Also, it checks the timeout.
 */
void ip_slow_timeout() {
	/* TODO: implement */
}

/**
 * this function is called by KENS_dispatch_loop() in Kernel_main.c .
 * Nothing has to be more inplemented in this function.
 */
int ip_dispatch() {
	ip_slow_timeout();
	return 0;
}

/**
 * This fuction is called by ip_input function when the incoming packet is
 * a fragment packet. 
 * You should add the fragment to a proper locaiton in reassembly list.
 * If reassembly is possible, reassemble the fragments.
 * @return 0 when success.
 */
int ip_reass(void *buf) {
	/* TODO: implement */
}

/**
 * this function is called for every incoming packet from datalink.
 * You should implement logic in this function or in serveral functions
 * to process incoming packets to this host as well as packets which
 * pass through this host, routing or forwarding.
 *
 * For further information, I strongly recommend you to refer TCP/IP
 * Illustrated Volume 2.
 *
 * @param buf buffer which contains data from datalink. this buffer starts
 * from KIP header
 * @param len exact size of data contained in buf
 * @return 0 when success, others when errors
 */
int ip_input(void *buf,int len)
{
	struct ip *ip;
	unsigned short hlen,dlen;

	ip = (struct ip *)buf;

	/* TODO: implement */

	dlen = ntohs((unsigned short)ip->ip_len);

	/* now it is ready to send to KTCP layer */
	tcp_dispatch_in(ip->ip_src,ip->ip_dst,buf+sizeof(struct ip),dlen);

	return 0;
}

/**
 * this function deals outgoing packet from this host. That is,
 * this function is directly called by Transport layer, KTCP.
 * You should implement logic to decide packet route which is sometimes
 * given by KTCP layer, fragment data and generate proper KIP header
 * for each outgoing packet. You may leave this function as a wrapper
 * to another extended KIP output function which receive an extra argument
 * ,flag, to share the facilities with packet forwarding.
 *
 * For further information, I strongly recommend you to refer TCP/IP
 * Illustrated Volume 2.
 *
 * @param src where this packet comes from in network byte order.
 * @param dst where this packet goes to in network byte order.
 * @param buf packet's payload
 * @param len length of packet's payload
 * @param ro routing information which is already cached by previous call.
 * If this argument is not null and the structure is empty, ip_output will
 * fill the structure with proper routing information for next time use.
 * If this argument is not null and the structure is not empty, ip_output will
 * use given routing information without lookup routing table.
 * @return 0 when success, others when errors
 */
int ip_output(struct in_addr src,struct in_addr dst,
		void *buf,size_t len,route *ro)
{
	unsigned char *pkt = buf;
	int hlen = sizeof(struct ip);
	struct ip *ip;
	struct in_addr dst2;
	ifnet *ifp = NULL;
	unsigned char ip_buf[MAX_PACKET_SIZE];

	memcpy(ip_buf+20,pkt,len);	/* copy TCP packet into local buffer */
	ip = (struct ip *)ip_buf;	/* may grab first 20 bytes */

	ip->ip_v = 4;	/* version 4 */
	ip->ip_hl = hlen >> 2;
	ip->ip_len = len;
	ip->ip_ttl = KIP_DEFAULT_TTL;

	ifp = ifunit("lo");

	dst2.s_addr = inet_addr("127.0.0.1");
	ip->ip_src.s_addr = dst2.s_addr;
	ip->ip_dst.s_addr = dst2.s_addr;
	
	/* TODO: implement */
	
	ip->ip_len = htons((unsigned short)ip->ip_len);
	ip->ip_off = htons((unsigned short)ip->ip_off);

	dl_output(ifp,ip_buf,hlen+len,dst2);

	return 0;
}

/**
 * get virtual ip address of virtual network interface card
 * which is used to transmit a packet destined to 'in'.
 * this is called by TCP layer to decide source ip address
 * for outgoing packet. Thus, you should consult routing table
 * to figure out which device should be used.
 * @param in destination of a packet in network byte order
 * @return source ip address of interface card in network byte order
 */
uint32_t ip_host_address(struct in_addr in)
{
	route ro;	
	ifnet *ifp;

	for ( ifp = _ifnet; ifp; ifp = ifp->if_next )
		if ( in_localnet(ifp,in) )
			return IN_ADDR(ifp).s_addr;

	ro.ro_dst.s_addr = in.s_addr;
	ro.ro_rt = NULL;

	rt_alloc(&ro);

	if ( ro.ro_rt == NULL )
		return htonl(INADDR_ANY);

	return IN_ADDR(ro.ro_rt->rt_ifp).s_addr;
}

/**
 * dump given KIP header into log file.
 * @param title a header for each log
 * @param ip a KIP header to dump
 */
static void ip_dump_header(char *title,struct ip *ip)
{
	char buf[80];

	inet_ntoa_r(ip->ip_src,buf,80);

	L_IP_HDR("%s v = %d src = %s dest = %s ttl = %d",
			title,
			ip->ip_v,
			buf,
			inet_ntoa(ip->ip_dst),
			ip->ip_ttl
	);
}


/*
 * kip.h
 * 
 * CS244A Winter 2001 (Assignment #3)
 *
 */


/* header file for the transport layer */

#ifndef _KIP_H_
#define _KIP_H_

#include <netinet/in.h>

#include "iniparser.h"

#include "route.h"

#define KIP_HEADER_SIZE	20
#define KIP_DEFAULT_TTL	7

extern int ip_init(dictionary *conf);
extern int ip_shutdown(void);
extern int ip_input(void *buf,int len);
extern int ip_output(struct in_addr src,struct in_addr dst,void *buf,size_t len,route *ro);
extern int ip_dispatch();

uint32_t ip_host_address(struct in_addr in);

#endif


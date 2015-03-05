#include <stdio.h>
#include "CuTest.h"
#include "ktcp.h"
#include "route.h"
#include "KtcpTest.h"

#if defined (HAVE_DMALLOC_H) && defined (HAVE_LIBDMALLOC)
#include "dmalloc.h"
#endif

CuSuite* KtcpGetSuite()
{
	CuSuite* suite = CuSuiteNew();
	initTest();
	SUITE_ADD_TEST(suite, TestBind);
	SUITE_ADD_TEST(suite, TestListen);
	SUITE_ADD_TEST(suite, TestAccept);
	SUITE_ADD_TEST(suite, TestConnect);
	SUITE_ADD_TEST(suite, TestSendSegment1);
	SUITE_ADD_TEST(suite, TestSendSegment2);
	SUITE_ADD_TEST(suite, TestSendSegment3);
	SUITE_ADD_TEST(suite, TestFindCtx);
	SUITE_ADD_TEST(suite, TestCreateCtx);
	SUITE_ADD_TEST(suite, TestDispatchPending);
	SUITE_ADD_TEST(suite, TestChangeState1);
	SUITE_ADD_TEST(suite, TestChangeState2);
	SUITE_ADD_TEST(suite, TestClose3);
	SUITE_ADD_TEST(suite, TestCleanupTimewaitCtx);
	SUITE_ADD_TEST(suite, TestAddToMyStream);
	SUITE_ADD_TEST(suite, TestSendStream4);
	SUITE_ADD_TEST(suite, TestAcceptPeerACK3);
	SUITE_ADD_TEST(suite, TestAcceptPeerACK4);
	SUITE_ADD_TEST(suite, TestAcceptPeerSYN);
	SUITE_ADD_TEST(suite, TestAcceptPeerFIN);
	SUITE_ADD_TEST(suite, TestAddToPeerStream);
	SUITE_ADD_TEST(suite, TestRecvStream);
	SUITE_ADD_TEST(suite, TestRetransmit4);
	return suite;
}


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
	SUITE_ADD_TEST(suite, TestFindCtx);
	SUITE_ADD_TEST(suite, TestCreateCtx);
	SUITE_ADD_TEST(suite, TestDispatchPending);
	SUITE_ADD_TEST(suite, TestChangeState1);
	return suite;
}


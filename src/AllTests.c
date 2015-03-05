

/* This is auto-generated code. Edit at your own peril. */

#include "CuTest.h"


void RunAllTests(void) 
{
    CuString *output = CuStringNew();
    CuSuite* suite = KtcpGetSuite();

    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);
}

int main(void)
{
    RunAllTests();
}


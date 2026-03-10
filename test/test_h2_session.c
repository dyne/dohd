/* dohd test unit for HTTP/2 session helpers */

#include <stdio.h>
#include "../src/h2_session.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        return 0; \
    } \
    tests_passed++; \
    fprintf(stderr, "PASS: %s\n", msg); \
} while (0)

static int test_stream_close_ignores_detached_stream(void)
{
    TEST_ASSERT(dohd_h2_stream_close_action(0, 0) ==
            DOHD_H2_STREAM_CLOSE_IGNORE,
            "stream close ignores missing request");
    TEST_ASSERT(dohd_h2_stream_close_action(1, 0) ==
            DOHD_H2_STREAM_CLOSE_IGNORE,
            "stream close ignores owner mismatch");
    return 1;
}

static int test_stream_close_destroys_owned_request(void)
{
    TEST_ASSERT(dohd_h2_stream_close_action(1, 1) ==
            DOHD_H2_STREAM_CLOSE_DESTROY,
            "stream close destroys matching request");
    return 1;
}

int main(void)
{
    int ok = 1;

    fprintf(stderr, "=== HTTP/2 Session Helper Tests ===\n");

    ok &= test_stream_close_ignores_detached_stream();
    ok &= test_stream_close_destroys_owned_request();

    fprintf(stderr, "\n%d/%d tests passed\n", tests_passed, tests_run);
    return ok ? 0 : 1;
}

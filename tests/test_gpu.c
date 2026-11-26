#include "gpu.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define MIB (1024ULL * 1024ULL)

static void test_nvidia_valid(void) {
    GpuInfo g;

    memset(&g, 0, sizeof(g));
    assert(gpu_parse_nvidia_csv("12, 1024, 8192, 2100\n", &g) == 0);
    assert(g.present == 1);
    assert(g.util_pct == 12);
    assert(g.mem_used_bytes == 1024ULL * MIB);
    assert(g.mem_total_bytes == 8192ULL * MIB);
    assert(g.clock_mhz == 2100);
    assert(strcmp(g.vendor, "NVIDIA") == 0);

    /* tabs, no spaces, no trailing newline */
    assert(gpu_parse_nvidia_csv("\t3 ,  256,512,  900", &g) == 0);
    assert(g.util_pct == 3);
    assert(g.mem_used_bytes == 256ULL * MIB);
    assert(g.mem_total_bytes == 512ULL * MIB);
    assert(g.clock_mhz == 900);

    assert(gpu_parse_nvidia_csv("0, 0, 8192, 210", &g) == 0);
    assert(g.util_pct == 0);
    assert(g.mem_used_bytes == 0);

    /* only the first line is used (multi-GPU output) */
    assert(gpu_parse_nvidia_csv("5, 100, 200, 300\n7, 1, 2, 3\n", &g) == 0);
    assert(g.util_pct == 5);
    assert(g.mem_total_bytes == 200ULL * MIB);

    /* [N/A] clocks are tolerated as "unknown" */
    assert(gpu_parse_nvidia_csv("44, 512, 8192, [N/A]\n", &g) == 0);
    assert(g.util_pct == 44);
    assert(g.clock_mhz == 0);
    assert(gpu_parse_nvidia_csv("44, N/A, 8192, 1500\n", &g) == 0);
    assert(g.mem_used_bytes == 0);
    assert(g.clock_mhz == 1500);

    /* utilization above 100 is clamped */
    assert(gpu_parse_nvidia_csv("150, 1, 2, 3", &g) == 0);
    assert(g.util_pct == 100);
}

static void test_nvidia_malformed(void) {
    GpuInfo g;
    GpuInfo sentinel;

    memset(&sentinel, 0x5a, sizeof(sentinel));
    sentinel.util_pct = -7;

    g = sentinel;
    assert(gpu_parse_nvidia_csv(NULL, &g) == -1);
    assert(gpu_parse_nvidia_csv("", &g) == -1);
    assert(gpu_parse_nvidia_csv("\n", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, 1024, 8192", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, 1024, 8192, 2100, 1", &g) == -1);
    assert(gpu_parse_nvidia_csv("12 1024 8192 2100", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, x, 8192, 2100", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, 1024, 8192, 2100MHz", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, 1024, 8192, 2100 junk", &g) == -1);
    assert(gpu_parse_nvidia_csv(", 1024, 8192, 2100", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, 1024, 8192, [N/A]x", &g) == -1);
    /* out is untouched after a failure */
    assert(g.util_pct == -7);
    assert(gpu_parse_nvidia_csv("12, 1024, 8192, 2100", NULL) == -1);
}

static void test_nvidia_negative(void) {
    GpuInfo g;

    assert(gpu_parse_nvidia_csv("-1, 1024, 8192, 2100", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, -1, 8192, 2100", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, 1024, -8192, 2100", &g) == -1);
    assert(gpu_parse_nvidia_csv("12, 1024, 8192, -2100", &g) == -1);
}

static void test_amd_sclk(void) {
    unsigned mhz = 0;

    assert(gpu_parse_amd_sclk("0: 500Mhz\n1: 2100Mhz *\n2: 1800Mhz\n", &mhz) == 0);
    assert(mhz == 2100);

    assert(gpu_parse_amd_sclk("0: 500Mhz *\n1: 2100Mhz\n", &mhz) == 0);
    assert(mhz == 500);

    assert(gpu_parse_amd_sclk("1: 1750Mhz *\r\n", &mhz) == 0);
    assert(mhz == 1750);

    assert(gpu_parse_amd_sclk("1:1750Mhz*", &mhz) == 0);
    assert(mhz == 1750);

    /* no marked line */
    assert(gpu_parse_amd_sclk("0: 500Mhz\n1: 2100Mhz\n", &mhz) == -1);
    assert(gpu_parse_amd_sclk("", &mhz) == -1);
    assert(gpu_parse_amd_sclk(NULL, &mhz) == -1);
    assert(gpu_parse_amd_sclk("0: 500Mhz *\n", NULL) == -1);
    /* marker without a number */
    assert(gpu_parse_amd_sclk("current *\n", &mhz) == -1);
    assert(gpu_parse_amd_sclk("0: 500Mhz\n", &mhz) == -1);
}

static void test_live_read(void) {
    GpuInfo g;
    int rc;

    assert(gpu_read(NULL) == -1);

    memset(&g, 0xff, sizeof(g));
    rc = gpu_read(&g);
    if (rc == 0) {
        assert(g.present == 1);
        assert(g.util_pct == -1 || (g.util_pct >= 0 && g.util_pct <= 100));
        assert(g.vendor[0] != '\0');
        printf("gpu_read: vendor=%s util=%d mem=%" PRIu64 "/%" PRIu64 " clock=%u\n",
               g.vendor, g.util_pct, g.mem_used_bytes, g.mem_total_bytes,
               g.clock_mhz);
    } else {
        assert(rc == -1);
        assert(g.present == 0);
        assert(g.util_pct == 0);
        printf("gpu_read: no GPU source available (-1)\n");
    }
}

int main(void) {
    test_nvidia_valid();
    test_nvidia_malformed();
    test_nvidia_negative();
    test_amd_sclk();
    test_live_read();
    printf("test_gpu: all assertions passed\n");
    return 0;
}

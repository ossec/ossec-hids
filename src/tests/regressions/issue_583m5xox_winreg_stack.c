/*
 * ANT-2026-583M5XOX: os_winreg_querykey() must not hold ~38 KB of
 * RegEnumValue buffers on every recursive frame.
 *
 * The syscheck thread gets a 2 MB stack. With the large buffers in the
 * recursive frame, about 55 nested registry keys overflow it and kill the
 * Windows agent. The Makefile compiles win-registry.c with -fstack-usage and
 * passes the measured frame size as QUERYKEY_FRAME.
 *
 * Build (from src/):
 *   make -f tests/regressions/Makefile issue_583m5xox_winreg_stack
 */

#include <stdio.h>

#ifndef QUERYKEY_FRAME
# error "QUERYKEY_FRAME must be set from win-registry.su"
#endif

/* After moving value hashing out of the recursive frame, the frame should
 * be well under 4 KB (observed ~688 bytes). Pre-fix it is ~37856. */
#define QUERYKEY_FRAME_LIMIT 4096

int main(void)
{
    printf("ANT-2026-583M5XOX winreg stack frame regression\n");
    printf("  os_winreg_querykey frame: %d bytes\n", QUERYKEY_FRAME);

    if (QUERYKEY_FRAME > QUERYKEY_FRAME_LIMIT) {
        printf("  FAIL: frame %d exceeds %d (large buffers still on the "
               "recursive stack)\n",
               QUERYKEY_FRAME, QUERYKEY_FRAME_LIMIT);
        return (1);
    }

    printf("  ok:   recursive frame is within %d bytes\n",
           QUERYKEY_FRAME_LIMIT);
    printf("all checks passed\n");
    return (0);
}

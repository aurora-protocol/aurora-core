#include <stddef.h>

void aurora_core_secure_zero(void *p, size_t length) {
    volatile unsigned char *bytes = p;
    while (length-- > 0) {
        *bytes++ = 0;
    }
}

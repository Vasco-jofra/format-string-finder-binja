#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdarg.h>

// ====================
// printf like functions
void PRINTF_LIKE_1(char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    printf (fmt, args);

    va_end(args);
}

void PRINTF_LIKE_2(int n, char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    printf("%d", n);
    printf (fmt, args);

    va_end(args);
}

// ====================
// safe printf usage
void SAFE_fs() {
    printf("%d\n", 0xdeadbeef);
}

void SAFE_phi(int b) {
    char *fmt;
    if (b) {
        fmt = "Path 1";
    } else {
        fmt = "Path 2";
    }

    printf(fmt);
}

void SAFE_phi_2_deep(int b, int b2) {
    char *fmt;
    if (b) {
        if (b2) {
            fmt = "Path 1.1";
        } else {
            fmt = "Path 1.2";
        }
        printf(fmt);
    } else {
        fmt = "Path 2";
    }
    char *fmt2 = fmt;
    printf(fmt2);
}

void SAFE_fs_second_order_arg_0() {
    PRINTF_LIKE_1("I'm so safe\n");
}

void SAFE_fs_second_order_arg_1() {
    PRINTF_LIKE_2(10, "I'm so very safe\n");
}

// ====================
// vulnerable printf usage
void VULN_fs_local() {
    char c[64] = {0};
    read(0, c, 64);

    printf(c);
}

char g_fs[64] = "Hello";
void VULN_fs_global() {
    printf(g_fs);
}

void VULN_fs_heap() {
    char *f = (char *) calloc(64, 1);
    printf(f);
}

void VULN_fs_second_order_arg_0() {
    char c[64] = {0};
    read(0, c, 64);

    PRINTF_LIKE_1(c);
}

void VULN_fs_second_order_arg_1() {
    char c[64] = {0};
    read(0, c, 64);

    PRINTF_LIKE_2(10, c);
}

void VULN_phi(int b) {
    char *fmt;

    if (b) {
        read(0, fmt, 64);
    } else {
        fmt = "Path 2";
    }

    printf(fmt);
}

int main() {
    return 0;
}
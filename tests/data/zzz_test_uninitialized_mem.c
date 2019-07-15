// ====================
// utils
void putint(uint64_t a) {
    printf("%lu\n", a);
}

void test(uint64_t a, uint64_t b) {
    if (a > b) {
        putint(a);
    } else {
        putint(b);
    }
}

// ====================
// uninitialized mem tests
void uninit_mem_bad_local() {
    uint64_t a;
    putint(a);
}

void uninit_mem_good_local() {
    uint64_t a = 0xdeadbeef;
    uint64_t b = a + 23;
    putint(b);
}

uint64_t uninit_global;
void uninit_mem_good_global() {
    putint(uninit_global);
}


void uninit_mem_good_parameter(uint64_t a) {
    putint(a);
}

// =========================
// tests
void test_phi_2_deep(uint64_t b, uint64_t b2, uint64_t n) {
    uint64_t res;
    if (b) {
        if (b2) {
            res = n + b;
        } else {
            res = n + b + 3;
        }
        printf("%d", res);
    } else {
        res = b2 + 18;
    }
    putint(res);
}
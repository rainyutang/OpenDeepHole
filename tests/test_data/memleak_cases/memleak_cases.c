#define PRODUCT_NULL PRODUCT_PLATFORM_NULL
#define MY_NULL_VALUE PRODUCT_NULL

struct Owner {
    char *buf;
    char *last;
};

extern char *malloc(int size);
extern void free(void *ptr);
extern void release_buffer(char *ptr);
extern void consume(char *ptr);

int report_return_leak(int flag) {
    char *p = malloc(8);
    if (flag) {
        return -1;
    }
    free(p);
    return 0;
}

int report_branch_leak(int flag) {
    char *p = malloc(8);
    if (flag) {
        return -1;
    } else {
        free(p);
    }
    return 0;
}

int report_continue_leak(int bad) {
    for (;;) {
        char *q = malloc(16);
        if (q == PRODUCT_NULL) {
            continue;
        }
        if (bad) {
            continue;
        }
        release_buffer(q);
    }
}

int report_partial_multi(int flag) {
    char *p = malloc(8);
    char *q = malloc(16);
    if (flag) {
        free(p);
        return -1;
    }
    free(p);
    free(q);
    return 0;
}

int ok_null_macro_return(void) {
    char *p = malloc(8);
    if (p == PRODUCT_NULL) {
        return -1;
    }
    free(p);
    return 0;
}

int ok_init_failed_branch(void) {
    char *p = malloc(8);
    if (MY_NULL_VALUE == p) {
        return -1;
    }
    release_buffer(p);
    return 0;
}

int ok_null_initialized_before_allocation(int flag) {
    char *p = PRODUCT_NULL;
    if (flag) {
        return -1;
    }
    p = malloc(8);
    release_buffer(p);
    return 0;
}

int ok_param_transfer(char **out, int flag) {
    char *p = malloc(8);
    if (flag) {
        *out = p;
        return 0;
    }
    free(p);
    return 0;
}

int ok_param_member_transfer(struct Owner *owner, int flag) {
    char *p = malloc(8);
    if (flag) {
        owner->buf = p;
        return 0;
    }
    free(p);
    return 0;
}

int ok_member_base_null(struct Owner *owner) {
    if (owner == PRODUCT_NULL) {
        return -1;
    }
    release_buffer(owner->buf);
    return 0;
}

int ok_continue_null_branch(void) {
    for (;;) {
        char *q = malloc(16);
        if (q == PRODUCT_NULL) {
            continue;
        }
        release_buffer(q);
    }
}

int ok_continue_transfer(struct Owner *owner, int flag) {
    for (;;) {
        char *q = malloc(16);
        if (q == PRODUCT_NULL) {
            continue;
        }
        if (flag) {
            owner->last = q;
            continue;
        }
        release_buffer(q);
    }
}

int ok_loop_free_then_return(int count) {
    for (int i = 0; i < count; i++) {
        char *p = malloc(8);
        if (p == PRODUCT_NULL) {
            continue;
        }
        consume(p);
        free(p);
    }
    return 0;
}

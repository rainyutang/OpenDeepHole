/**
 * npd_test.c — Test cases for NPD (Null Pointer Dereference) detection.
 *
 * Contains both vulnerable (NPD) and safe patterns so we can verify
 * the checker correctly identifies candidates vs non-candidates.
 */

#include <stdlib.h>
#include <string.h>

typedef struct {
    int   value;
    char *name;
    struct Node *next;
} Node;

typedef int (*FuncPtr)(int);

/* Global function pointer — accessing it without null check is NPD */
FuncPtr g_callback = NULL;


/* ------------------------------------------------------------------ */
/*  VULNERABLE functions — should be flagged as NPD candidates         */
/* ------------------------------------------------------------------ */

/* V1: pointer parameter, arrow dereference, no null check */
int get_value(Node *node) {
    return node->value;   /* NPD: node might be NULL */
}

/* V2: malloc result used without NULL check */
char *make_buffer(int size) {
    char *buf = malloc(size);
    buf[0] = '\0';         /* NPD: malloc may return NULL */
    return buf;
}

/* V3: chained dereference — inner pointer not checked */
int get_next_value(Node *node) {
    if (node == NULL) {
        return -1;
    }
    return node->next->value;   /* NPD: node->next might be NULL */
}

/* V4: double pointer dereference */
int deref_double(Node **pp) {
    return (*pp)->value;   /* NPD: *pp might be NULL */
}

/* V5: function return value not checked */
Node *find_node(Node *head, int target) {
    Node *cur = head;
    while (cur != NULL && cur->value != target) {
        cur = cur->next;
    }
    return cur;  /* may be NULL if not found */
}

void use_find(Node *head) {
    Node *n = find_node(head, 42);
    int v = n->value;   /* NPD: n might be NULL */
    (void)v;
}

/* V6: global function pointer called without null check */
int call_global_fp(int x) {
    return g_callback(x);  /* NPD: g_callback might be NULL */
}

/* V7: pointer subscript without null check */
int sum_array(int *arr, int len) {
    int total = 0;
    for (int i = 0; i < len; i++) {
        total += arr[i];   /* NPD: arr might be NULL */
    }
    return total;
}


/* ------------------------------------------------------------------ */
/*  SAFE functions — should NOT be flagged (null checks present)       */
/* ------------------------------------------------------------------ */

/* S1: proper null check before arrow dereference */
int safe_get_value(Node *node) {
    if (node == NULL) {
        return -1;
    }
    return node->value;   /* safe */
}

/* S2: assert-guarded pointer */
void safe_use_ptr(Node *node) {
    assert(node != NULL);
    node->value = 0;      /* safe */
}

/* S3: early return on null */
char *safe_get_name(Node *node) {
    if (!node) {
        return NULL;
    }
    return node->name;    /* safe */
}

/* S4: malloc with null check */
int *safe_alloc(int n) {
    int *arr = malloc(n * sizeof(int));
    if (arr == NULL) {
        return NULL;
    }
    arr[0] = 0;           /* safe */
    return arr;
}

/* S5: ternary null check (challenging for simple regex, but listed for reference) */
int ternary_safe(Node *node) {
    return node != NULL ? node->value : -1;
}

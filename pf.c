#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void foo(const char *);
void bar(const char *f) { foo(f); }
int main(int argc, char *argv[]) {
    bar(argv[1]);
    return 0;
}
void foo(const char *f) {
    char buf[4096];
    memcpy(buf, f, strlen(f));
    printf(buf);
    printf("\n");
    printf("main=0x%08x\n", (int)main);
    printf("system=0x%08x\n", (int)system);
    printf("buf=0x%08x\n", (int)&buf);
    printf("%s", buf);
    return;
}

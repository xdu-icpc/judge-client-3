#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
    if (!fork()) // child
    {
        while (1)
        {
            fork();
        }
    }
    puts("hello, world");
    int *a = malloc(1024 * 1024 * 10);
    a[0] = 456;
    a[1024 * 1024 * 10 / sizeof(int) - 1] = 123;
    return 1;
}

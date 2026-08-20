#include <stdio.h>

int add(int a, int b)
{
    int total = a + b;
    return total;
}

int main(void)
{
    printf("%d\n", add(2, 3));
    return 0;
}

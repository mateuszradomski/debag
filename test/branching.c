void f()
{
}

void b()
{
}

int main()
{
    int a = 0;

    if(a % 2 == 0)
    {
        b();
    }
    else
    {
        f();
    }

    a += 1;

    if(a % 2 == 0)
    {
        b();
    }
    else
    {
        f();
    }

    return 0;
}

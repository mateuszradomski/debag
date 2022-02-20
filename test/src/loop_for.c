int main(void)
{
    int s = 0;
    
    for(int i = 0; i < 10; i++)
    {
        s += i;
    }
    
    int v = 0;
    
    for(int i = 0; i < 10; i++)
    {
        for(int j = 0; j < 10; j++)
        {
            v += j * i;
        }
    }
    
    return 0;
}
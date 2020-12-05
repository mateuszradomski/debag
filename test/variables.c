typedef float real32;

real32 global_variable = 3.1459f;

struct vec2
{
    real32 x;
    float y;
};

struct swarray
{
    real32 index;
    int inside_array[12];
};

struct asssss
{
    
    int a;
    int b;
    int c;
    int d;
    int e;
    int f;
    int g;
    int h;
    int i;
    int j;
    int k;
    int l;
    int m;
    int n;
    int o;
    int p;
    int r;
    int s;
    int t;
    
};

int main()
{
    real32 X = 0.5;
    float ssss = 234.3;
    
    struct vec2 myVec2 = {0};
    
    struct asssss asdf;
    struct asssss asdf1;
    struct asssss asdf2;
    
    float *floatotreal32pointer = &X;
    real32 *real32tofloatpoiter = &ssss;
    
    float array[16] = { 1.0f, 0.0f, 2.0f };
    struct vec2 myVec2s[3] = { 1.0f };
    struct swarray stresstest[2] = {};
    
    real32 Result = X * ssss;
}

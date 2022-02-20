#include <stdio.h>

typedef unsigned int u32;

struct test
{
    const char *Name;
    u32 (*FuncPointer)(void);

    u32 Magic;
};

u32 ErrorBufferSet = 0;
char ErrorBuffer[1024] = { };

#define ANSI_RED "\033[0;31m"
#define ANSI_GREEN "\033[0;32m"
#define ASNI_RESET "\033[0m"

#define Stringify(x) #x
#define TEST_MAGIC 0xff4ef209
#define TEST_NAME(Name) Name##_Struct
#define TEST_ADD(Name) \
    static test TEST_NAME(Name) __attribute__ ((used, section (".tests"), aligned(1))) { \
        Stringify(Name), \
        Name, \
        TEST_MAGIC, \
    }; \

#define EXPECT_EQ(x, y) \
{\
    if((x) != (y)) \
    {\
        sprintf(ErrorBuffer, "expected equal but [x!=y] : [%u, %u]", (x), (y));\
        ErrorBufferSet = 1; \
        return 1;\
    }\
}\

#define TEST(Name) \
    u32 Name(); \
    TEST_ADD(Name) \
    u32 Name() \

TEST(DummyHead) { return 0; }

TEST(FirstTest)
{

    return 0;
}

TEST(SecondTestThatFails)
{

    return 1;
}

TEST(ThirdTestThatFailsOnExpectEq)
{
    EXPECT_EQ(2+2, 5);
    return 0;
}

TEST(FourthTestThatPassesOnExpectEq)
{
    EXPECT_EQ(2+2, 4);
    return 0;
}

int main()
{
    test *TestList = &TEST_NAME(DummyHead);
    // Skip the first test since it's only a dummy to help find other tests 
    TestList++;

    u32 Passed = 0, Total = 0;
    while(true)
    {
        test *Test = TestList;

        // If no magic, we did not create this entry
        if(Test->Magic != TEST_MAGIC)
        {
            break;
        }

        u32 Result = Test->FuncPointer();
        u32 TestFailed = Result != 0;

        char *VerdictColor, *VerdictString, *ResetColor;
        Total += 1;
        if(TestFailed)
        {
            VerdictColor  = ANSI_RED;
            VerdictString = "FAILED";
            ResetColor    = ASNI_RESET;
        }
        else
        {
            VerdictColor  = ANSI_GREEN;
            VerdictString = "PASS";
            ResetColor    = ASNI_RESET;
            Passed += 1;
        }

        printf("TEST %d/%d %s %s[%s]%s\n", Passed, Total, Test->Name, VerdictColor, VerdictString, ResetColor);
        
        if(TestFailed && ErrorBufferSet)
        {
            printf("TEST   %s\n", ErrorBuffer);
        }

        TestList++;
    }

    return 0;
}

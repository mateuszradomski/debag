/* date = December 19th 2020 6:27 pm */

#ifndef UTILS_H
#define UTILS_H

struct Data
{
    u8 *Ptr;
    u32 Len;
};

struct TableU32U32
{
    u32 *Keys;
    u32 *Values;
    u32 Count;
    u32 Size;
};

struct BinSearchRes
{
    u32 Index : 31;
    u32 Found : 1;
};

enum
{
    ORD_NONE,
    ORD_LT,
    ORD_EQ,
    ORD_GT,
};

typedef i32 OrderingType;

static BinSearchRes BinarySearch(void *Array, u32 Cnt, u32 Stride, u32 AtomSize, OrderingType (* Predicate)(void *, void *), void *UserPtr);

#endif //UTILS_H

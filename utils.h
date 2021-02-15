/* date = December 19th 2020 6:27 pm */

#ifndef UTILS_H
#define UTILS_H

struct TableU32U32
{
    u32 *Keys;
    u32 *Values;
    u32 Count;
    u32 Size;
};

struct bin_search_res
{
    u32 Index : 31;
    u32 Found : 1;
};

enum ordering
{
    ORD_NONE,
    ORD_LT,
    ORD_EQ,
    ORD_GT,
};

typedef i32 ordering_type;

static bin_search_res BinarySearch(void *Array, u32 Cnt, u32 Stride, u32 AtomSize, ordering_type (* Predicate)(void *, void *), void *UserPtr);

#endif //UTILS_H

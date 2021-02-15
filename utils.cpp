static TableU32U32
TableU32U32Make(u32 Buckets)
{
    void *Memory = (void *)calloc(1, sizeof(u32) * 2 * Buckets);
    
    TableU32U32 Table = {};
    
    Table.Keys = (u32 *)Memory;
    Table.Values = (u32 *)Memory + Buckets;
    Table.Size = Buckets;
    
    return Table;
}

static void
TableFree(TableU32U32 *Table)
{
    free(Table->Keys);
}

static i32
TableLookup(TableU32U32 *Table, u32 Key)
{
    i32 Result = -1;
    
    for(u32 I = 0; I < Table->Count; I++)
    {
        if(Table->Keys[I] == Key)
        {
            Result = I;
            break;
        }
    }
    
    return Result;
}

static bool
TableRead(TableU32U32 *Table, u32 Key, u32 *ValOut)
{
    i32 Idx = TableLookup(Table, Key);
    
    if(Idx < 0)
    {
        return false;
    }
    
    *ValOut = Table->Values[Idx];
    
    return true;
}

static bool
TableInsert(TableU32U32 *Table, u32 Key, u32 Value)
{
    int Idx = TableLookup(Table, Key);
    if(Idx < 0 && Table->Size < Table->Count)
    {
        Table->Keys[Table->Count] = Key;
        Table->Values[Table->Count] = Value;
        Table->Count += 1;
        return true;
    }
    else if(Idx > 0)
    {
        Table->Values[Idx] = Value;
        return true;
    }
    else if(Idx < 0 && Table->Size > Table->Count)
    {
        return false;
    }
    
    return false;
}

static bin_search_res
BinarySearch(void *Array, u32 Cnt, u32 Stride, u32 AtomSize, ordering_type (* Predicate)(void *, void *), void *UserPtr)
{
    bin_search_res Result = {};

    if(Cnt > 0)
    {
        i32 First = 0;
        i32 Last = Cnt - 1;
        i32 Middle = (First + Last) / 2;

        while(First <= Last)
        {
            ordering_type Order = Predicate((u8 *)Array + Stride + (Middle * AtomSize), UserPtr);

            if(Order == ORD_EQ)
            {
                Result.Found = true;
                Result.Index = Middle;
                return Result;
            }
            else
            {
                if(Order == ORD_LT)
                {
                    First = Middle + 1;
                }
                else if(Order == ORD_GT)
                {
                    Last = Middle - 1;
                }
                else
                {
                    assert(false && "Invalid code path");
                }
            }

            Middle = (First + Last) / 2;
        }

        if(First > Last)
        {
            Result.Found = false;
        }
    }

    return Result;
}

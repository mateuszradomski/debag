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
static BinSearchRes
BinarySearch(void *Array, u32 Cnt, u32 Stride, u32 AtomSize, OrderingType (* Predicate)(void *, void *), void *UserPtr)
{
    BinSearchRes Result = {};

    if(Cnt > 0)
    {
        i32 First = 0;
        i32 Last = Cnt - 1;
        i32 Middle = (First + Last) / 2;

        while(First <= Last)
        {
            OrderingType Order = Predicate((u8 *)Array + Stride + (Middle * AtomSize), UserPtr);

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

static memory_cursor_node *
ArenaNewNode(arena *Arena, size_t Size)
{
    memory_cursor_node *Result = 0x0;
    Size = MAX(Arena->ChunkSize, Size);
    
    void *Memory = (u8 *)malloc(Size + sizeof(memory_cursor_node));
    assert(Memory);

    Result = (memory_cursor_node *)Memory;
    
    Result->Cursor.BasePtr = (u8 *)Memory + sizeof(memory_cursor_node);
    Result->Cursor.CursorPtr = Result->Cursor.BasePtr;
    Result->Cursor.Size = Size;
    SLL_STACK_PUSH(Arena->CursorNode, Result);

    CursorClear(&Result->Cursor);

    return Result;
}

static void
CursorClear(memory_cursor *Cursor, u8 ClearTo)
{
    memset(Cursor->BasePtr, ClearTo, Cursor->Size);
    Cursor->CursorPtr = Cursor->BasePtr;
}

static void
CursorDestroy(memory_cursor *Cursor)
{
    if(Cursor && Cursor->BasePtr)
    {
        void *Ptr = (u8 *)Cursor->BasePtr - sizeof(memory_cursor_node);

        free(Ptr);
    }
}

static size_t
CursorFreeBytes(memory_cursor *Cursor)
{
    size_t Result = Cursor->Size - (size_t)(Cursor->CursorPtr - Cursor->BasePtr);
    
    return Result;
}

static arena
ArenaCreate(size_t ChunkSize, size_t Aligment)
{
    arena Result = {};

    Result.ChunkSize = ChunkSize;
    Result.Aligment = Aligment;

    return Result;
}

static arena
ArenaCreate(size_t Size)
{
    arena Result = ArenaCreate(Kilobytes(16), 8);

    ArenaNewNode(&Result, Size);
    
    return Result;
}

static arena
ArenaCreateZeros(size_t Size)
{
    arena Result = {};
    
    Result = ArenaCreate(Size);
    CursorClear(&Result.CursorNode->Cursor);
    
    return Result;
}

static void
ArenaClear(arena *Arena)
{
    for(memory_cursor_node *CursorNode = Arena->CursorNode;
        CursorNode != 0x0;
        CursorNode = CursorNode->Next)
    {
        CursorClear(&CursorNode->Cursor);
    }
}

static void
ArenaDestroy(arena *Arena)
{
    if(Arena)
    {
        memory_cursor_node *ToDestroy = 0x0;
        for(memory_cursor_node *CursorNode = Arena->CursorNode;
            CursorNode != 0x0;
            CursorNode = CursorNode->Next)
        {
            if(ToDestroy)
            {
                CursorDestroy(&ToDestroy->Cursor);
            }
            
            ToDestroy = CursorNode;
        }

        if(ToDestroy)
        {
            CursorDestroy(&ToDestroy->Cursor);
        }
    }
}

static void *
ArenaPush(arena *Arena, size_t Size)
{
    void *Result = 0x0;

    assert(Arena);
    
    if(Size)
    {
        memory_cursor_node *CursorNode = Arena->CursorNode;
        if(!CursorNode)
        {
            CursorNode = ArenaNewNode(Arena, Size);
        }

        memory_cursor *Cursor = &CursorNode->Cursor;
        size_t BytesLeft = CursorFreeBytes(Cursor);
        // Calculates how many bytes we need to add to be aligned on the 16 bytes.
        size_t PaddingNeeded = (0x10 - ((size_t)Cursor->CursorPtr & 0xf)) & 0xf;
        
        if(Size + PaddingNeeded > BytesLeft)
        {
            CursorNode = ArenaNewNode(Arena, Size + PaddingNeeded);
            Cursor = &CursorNode->Cursor;
        }

        Cursor->CursorPtr += PaddingNeeded;
        Result = Cursor->CursorPtr;
        Cursor->CursorPtr += Size;
    }
    
    return Result;
}

scratch_arena::scratch_arena(size_t Size)
{
    this->Arena = ArenaCreateZeros(Size);
}

scratch_arena::scratch_arena() :
    scratch_arena(Kilobytes(16))
{
}

scratch_arena::operator arena*()
{
    return &this->Arena;
}

scratch_arena::~scratch_arena()
{
    ArenaDestroy(&this->Arena);
}

static void
HexDump(void *Ptr, size_t Count)
{
    for(u32 I = 0; I < Count; I++)
    {
        printf("%02x", ((u8 *)Ptr)[I]);

        if((I + 1) % 4 == 0)
        {
            printf(" ");
        }

        if((I + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    
    printf("\n");
}

static inline bool
AddressBetween(size_t Address, size_t Lower, size_t Upper)
{
    bool Result = false;
    
    Result = (Address >= Lower) && (Address <= Upper);
    
    return Result;
}

static inline bool
AddressBetween(size_t Address, address_range Range)
{
	bool Result = false;

	Result = AddressBetween(Address, Range.Start, Range.End);

	return Result;
}

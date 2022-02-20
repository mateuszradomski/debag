/* date = December 19th 2020 6:27 pm */

#ifndef UTILS_H
#define UTILS_H

typedef char i8;
typedef short i16;
typedef int i32;
typedef long i64;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef float f32;
typedef double f64;

#define TO_LOWERCASE(C) ((C) | (1 << 5))
#define IS_PRINTABLE(C) ((C) >= ' ' && (C) <= '~')

#define Kilobytes(x) ((x) * 1024)

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define ARRAY_LENGTH(a) (sizeof((a))/sizeof((a)[0]))

struct Data
{
    u8 *Ptr;
    u32 Len;
};

struct BinSearchRes
{
    u32 Index : 31;
    u32 Found : 1;
};

struct address_range
{
    size_t Start;
    size_t End;
};

struct memory_cursor
{
    u8* BasePtr;
    u8* CursorPtr;
    size_t Size;
};

struct memory_cursor_node
{
    memory_cursor_node *Next;
    memory_cursor Cursor;
};

struct arena
{
    memory_cursor_node *CursorNode;
    size_t ChunkSize;
    size_t Aligment;
};

struct scratch_arena
{
    arena Arena;

    scratch_arena(size_t Size);
    scratch_arena();
    operator arena*();
    ~scratch_arena();
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

/*
 * Arena functions
 */

static memory_cursor_node * ArenaNewNode(arena *Arena, size_t Size);
static void                 CursorClear(memory_cursor *Cursor, u8 ClearTo = 0);
static void                 CursorDestroy(memory_cursor *Cursor);
static size_t               CursorFreeBytes(memory_cursor *Cursor);

static arena    ArenaCreate(size_t ChunkSize, size_t Aligment);
static arena    ArenaCreate(size_t Size);
static arena    ArenaCreateZeros(size_t Size);
static void     ArenaClear(arena *Arena);
static void     ArenaDestroy(arena *Arena);
static void *   ArenaPush(arena *Arena, size_t Size);
static size_t   ArenaFreeBytes(arena *Arena);

#define ArrayPush(a,T,c) ((T *)ArenaPush((a), sizeof(T)*(c)))
#define StructPush(a, T) ((T *)ArenaPush((a), sizeof(T)))
#define BytesPush(a, c) (ArenaPush((a), (c)))

/*
 * Common functions that everyone can use
 */
static void     HexDump(void *Ptr, size_t Count);
static bool     AddressBetween(size_t Address, size_t Lower, size_t Upper);
static bool		AddressBetween(size_t Address, address_range Range);

#endif //UTILS_H

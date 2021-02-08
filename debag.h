/* date = November 18th 2020 7:33 pm */

#ifndef DEBAG_H
#define DEBAG_H

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

#define DWARF_CALL(x) assert((x) == DW_DLV_OK)

#define Kilobytes(x) ((x) * 1024)
#define ArrayPush(a,T,c) ((T *)ArenaPush((a), sizeof(T)*(c)))

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define ARRAY_LENGTH(a) (sizeof((a))/sizeof((a)[0]))

#define TIMER_START(id) clock_gettime(CLOCK_REALTIME, &TPoints[(id)].start);
#define TIMER_END(id) clock_gettime(CLOCK_REALTIME, &TPoints[(id)].end); printf("Timer %d finished in %ld us\n", (id), (TPoints[(id)].end.tv_nsec - TPoints[(id)].start.tv_nsec) / 1000);

#ifdef DEBUG
#define LOG_MAIN(fmt, ...) if(Debuger.Log.MainLogs) { printf(fmt, ##__VA_ARGS__); }
#else
#define LOG_MAIN(...) do { } while (0)
#endif

#define CLEAR_BREAKPOINTS 1

struct TimePoints
{
    struct timespec start;
    struct timespec end;
};

static TimePoints TPoints[32] = {};

struct button
{
    u8 Down    : 1;
    u8 Last    : 1;
    u8 Pressed : 1;
    u8 Repeat  : 1;
};

struct keyboard_modifiers
{
    u8 Shift    : 1;
    u8 Control  : 1;
    u8 Alt      : 1;
    u8 Super    : 1;
    u8 CapsLock : 1;
    u8 NumLock  : 1;
};

struct breakpoint_state
{
    u8 Enabled : 1;
    u8 ExectuedSavedOpCode : 1;
};

struct breakpoint
{
    size_t Address;
    size_t SavedOpCodes;
    u32 SourceLine;
    u32 FileIndex;
    breakpoint_state State;
};

enum
{
    INST_TYPE_NULL = 0x0,
    INST_TYPE_JUMP = 0x1,
    INST_TYPE_CALL = 0x2,
    INST_TYPE_RET = 0x4,
    INST_TYPE_RELATIVE_BRANCH = 0x8,
};

typedef i32 inst_type;

struct disasm_inst
{
    size_t Address;
    char *Mnemonic;
    char *Operation;
};

struct address_range
{
    size_t Start;
    size_t End;
};

union x64_registers
{
    struct
    {
        size_t RAX;
        size_t RBX;
        size_t RCX;
        size_t RDX;
        size_t RDI;
        size_t RSI;
        
        size_t RBP;
        size_t RSP;
        
        size_t R8;
        size_t R9;
        size_t R10;
        size_t R11;
        size_t R12;
        size_t R13;
        size_t R14;
        size_t R15;
        
        size_t OrigRax;
        size_t Cs;
        size_t Eflags;
        size_t Ss;
        size_t FsBase;
        size_t GsBase;
        size_t Ds;
        size_t Es;
        size_t Fs;
        size_t Gs;
        
        size_t RIP;
    };
    size_t Array[27];
};

enum
{
    DEBUGEE_FLAG_NULL = 0,
    DEBUGEE_FLAG_RUNNING = (1 << 0),
    DEBUGEE_FLAG_STEPED = (1 << 1),
};

typedef i32 debugee_flag;

struct logging_switches
{
    bool DwarfLogs;
    bool VarLogs;
    bool MainLogs;
    bool DisasmLogs;
    bool FlowLogs;
};

struct dbg
{
    debugee_flag Flags;
    i32 DebugeePID;
    bool InputChange;
    char ProgramArgs[128];
    char PathToRunIn[256];
    char DebugeeProgramPath[256];
    size_t DebugeeLoadAddress;

    logging_switches Log;

    x64_registers Regs;
};

struct arena
{
    u8* BasePtr;
    u8* CursorPtr;
    size_t Size;
};

#define MAX_BREAKPOINT_COUNT 8
breakpoint *Breakpoints = 0x0;
u32 BreakpointCount = 0;

arena DisasmArena;
disasm_inst *DisasmInst = 0x0;
u32 DisasmInstCount = 0;

csh DisAsmHandle;
dbg Debuger;

button KeyboardButtons[GLFW_KEY_LAST] = {};
keyboard_modifiers KeyMods = {};

#define STMNT(S) do{ S }while(0)

#define SLL_STACK_PUSH_(H,N) N->Next=H,H=N
#define SLL_STACK_POP_(H) H=H=H->Next
#define SLL_QUEUE_PUSH_MULTIPLE_(F,L,FF,LL) if(LL){if(F){L->Next=FF;}else{F=FF;}L=LL;L->Next=0;}
#define SLL_QUEUE_PUSH_(F,L,N) SLL_QUEUE_PUSH_MULTIPLE_(F,L,N,N)
#define SLL_QUEUE_POP_(F,L) if (F==L) { F=L=0; } else { F=F->Next; }

#define SLL_STACK_PUSH(H,N) (SLL_STACK_PUSH_((H),(N)))
#define SLL_STACK_POP(H) (SLL_STACK_POP_((H)))
#define SLL_QUEUE_PUSH_MULTIPLE(F,L,FF,LL) STMNT( SLL_QUEUE_PUSH_MULTIPLE_((F),(L),(FF),(LL)) )
#define SLL_QUEUE_PUSH(F,L,N) STMNT( SLL_QUEUE_PUSH_((F),(L),(N)) )
#define SLL_QUEUE_POP(F,L) STMNT( SLL_QUEUE_POP_((F),(L)) )

static inline bool AddressBetween(size_t Address, size_t Lower, size_t Upper);
static arena ArenaCreate(size_t Size);
static arena ArenaCreateZeros(size_t Size);
static void ArenaClear(arena *Arena);
static void ArenaDestroy(arena *Arena);
static size_t ArenaFreeBytes(arena *Arena);
static void *ArenaPush(arena *Arena, size_t Size);
static void ButtonsUpdate(button *Buttons, u32 Count);
static bool CharInString(char *String, char C);
static void DeallocDebugInfo();
static void DebugeeContinueOrStart();
static void DebugeeRestart();
static void DebugeeStart();
static void DebugeeKill();
static void DebugerMain();
static void DisassembleAroundAddress(address_range AddrRange, i32 DebugeePID);
static char *DumpFile(arena *Arena, char *Path);
static void GLFWModsToKeyboardModifiers(int Mods);
static inst_type GetInstructionType(cs_insn *Instruction);
static u32 CapstoneRegisterToABINumber(x86_reg Register);
static size_t GetProgramCounter();
static inline size_t GetProgramCounterOffsetLoadAddress();
static size_t GetReturnAddress(size_t Address);
static size_t GetRegisterByABINumber(x64_registers Registers, u32 Number);
static char *GetRegisterNameByIndex(u32 Index);
static u64 HexStringToInt(char *String);
static void KeyboardButtonCallback(GLFWwindow *Window, int Key, int Scancode, int Action, int Mods);
static void MouseButtonCallback(GLFWwindow *Window, int Key, int Action, int Mods);
static void MousePositionCallback(GLFWwindow *Window, double X, double Y);
static user_regs_struct ParseToUserRegsStruct(x64_registers Regs);
static x64_registers ParseUserRegsStruct(user_regs_struct URS);
static size_t PeekDebugeeMemory(size_t Address, i32 DebugeePID);
static void PeekDebugeeMemoryArray(size_t StartAddress, u32 EndAddress, i32 DebugeePID, u8 *OutArray, u32 BytesToRead);
static x64_registers PeekRegisters(i32 DebugeePID);
static void SetRegisters(x64_registers Regs, i32 DebugeePID);
static void StringConcat(char *Dest, char *Src);
static void StringCopy(char *Dest, char *Src);
static u32 StringCountChar(char *String, char C);
static char *StringDuplicate(arena *Arena, char *Str);
static char *StringFindLastChar(char *String, char C);
static u32 StringLength(char *Str);
static void StringReplaceChar(char *Str, char Find, char Replace);
static void StringToArgv(char *Str, char **ArgvOut, u32 *Argc);
static bool StringsMatch(char *Str0, char *Str1);
static bool StringEmpty(char *Str);
static bool StringStartsWith(char *Str, char *Start);
static u32 StringSplit(char *Str, char Delimiter);
static char *StringSplitNext(char *Str);
static u32 StringSplitCountStarting(char *Lines, u32 LinesCount, char *Start);
static void UpdateInfo();
static void WindowSizeCallback(GLFWwindow *Window, i32 Width, i32 Height);

#endif //DEBAG_H

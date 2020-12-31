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

#define TIMER_START(id) clock_gettime(CLOCK_REALTIME, &TPoints[(id)].start);
#define TIMER_END(id) clock_gettime(CLOCK_REALTIME, &TPoints[(id)].end); printf("Timer %d finished in %ld us\n", (id), (TPoints[(id)].end.tv_nsec - TPoints[(id)].start.tv_nsec) / 1000);

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

struct breakpoint
{
    u64 Address;
    i32 DebugeePID;
    u8 SavedOpCode;
    bool Enabled;
    bool ExectuedSavedOpCode;
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
    char Mnemonic[16];
    char Operation[48];
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

        size_t RIP;
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

struct dbg
{
    debugee_flag Flags;
    i32 DebugeePID;
    bool InputChange;
    char ProgramArgs[128];
    char PathToRunIn[256];
    char DebugeeProgramPath[256];
    char BreakFuncName[128];
    char BreakAddress[32];
    void (* ModalFuncShow)();
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

#define MAX_DISASM_INSTRUCTIONS 1024
disasm_inst DisasmInst[MAX_DISASM_INSTRUCTIONS] = {};
u32 DisasmInstCount = 0;

csh DisAsmHandle;
x64_registers Regs;

dbg Debuger;

u32 WindowWidth = 1024;
u32 WindowHeight = 768;

button KeyboardButtons[GLFW_KEY_LAST] = {};
keyboard_modifiers KeyMods = {};

ImVec4 CurrentLineColor = ImVec4(1.0f, 1.0f, 0.0f, 1.0f);
ImVec4 BreakpointLineColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);

static void ImGuiStartFrame();
static void ImGuiEndFrame();
static void ImGuiShowVariable(size_t TypeOffset, size_t VarAddress, char *VarName);

static bool CharInString(char *String, char C);
static u32 StringCountChar(char *String, char C);
static u64 HexStringToInt(char *String);

static x64_registers PeekRegisters(i32 DebugeePID);
static void SetRegisters(x64_registers Regs, i32 DebugeePID);
static x64_registers ParseUserRegsStruct(user_regs_struct URS);
static user_regs_struct ParseToUserRegsStruct(x64_registers Regs);

static breakpoint *BreakpointFind(u64 Address, i32 DebugeePID);
static bool BreakpointEnabled(breakpoint *BP);
static breakpoint BreakpointCreate(u64 Address, i32 DebugeePID);
static void BreakpointEnable(breakpoint *BP);
static void BreakpointDisable(breakpoint *BP);

static address_range AddressRangeCurrentAndNextLine();
static void UpdateInfo();
static void ImGuiShowRegisters(user_regs_struct Regs);
static size_t PeekDebugeeMemory(size_t Address, i32 DebugeePID);
static void PeekDebugeeMemoryArray(u32 StartAddress, u32 EndAddress, i32 DebugeePID, u8 *OutArray, u32 BytesToRead);
static void DisassembleAroundAddress(address_range AddrRange, i32 DebugeePID);
static inst_type GetInstructionType(cs_insn *Instruction);
static size_t FindEntryPointAddress();

static bool AddressBetween(size_t Address, size_t Lower, size_t Upper);
static size_t GetRegisterByABINumber(x64_registers Registers, u32 Number);

static bool CharInString(char *String, char C);
static u32 StringCountChar(char *String, char C);
static void StringCopy(char *Dest, char *Src);
static void StringConcat(char *Dest, char *Src);
static bool StringsMatch(char *Str0, char *Str1);
static u64 HexStringToInt(char *String);
static char * DumpFile(char *Path);

static arena *ArenaCreate(size_t Size);
static void *ArenaPush(arena *Arena, size_t Size);
static void ArenaDestroy(arena *Arena);

static void DebugerMain();
static void DeallocDebugInfo();

#endif //DEBAG_H

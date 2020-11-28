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

#define DWARF_CALL(x) assert((x) == DW_DLV_OK)

struct button
{
    u8 Down : 1;
    u8 Last : 1;
    u8 Pressed : 1;
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

enum
{
    DBG_FLAG_NULL = 0x0,
    DBG_FLAG_CHILD_PROCESS_EXITED = 0x1,
};

typedef i32 dbg_flags;

struct dbg
{
    dbg_flags Flags;
    i32 DebugeePID;
    char *DebugeeProgramPath;
    bool InputChange;
    char ProgramArgs[128];
};

#define MAX_BREAKPOINT_COUNT 8
breakpoint *Breakpoints = 0x0;
u32 BreakpointCount = 0;

#define MAX_DISASM_INSTRUCTIONS 31
disasm_inst DisasmInst[MAX_DISASM_INSTRUCTIONS];
u32 DisasmInstCount = 0;

csh DisAsmHandle;
user_regs_struct Regs;

dbg Debuger;

button KeyboardButtons[GLFW_KEY_LAST] = {};

ImVec4 CurrentLineColor = ImVec4(1.0f, 1.0f, 0.0f, 1.0f);
ImVec4 BreakpointLineColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);

static void ImGuiStartFrame();
static void ImGuiEndFrame();

static bool CharInString(char *String, char C);
static u32 StringCountChar(char *String, char C);
static u64 HexStringToInt(char *String);

static user_regs_struct PeekRegisters(i32 DebugeePID);
static void SetRegisters(user_regs_struct Regs, i32 DebugeePID);

static breakpoint *BreakpointFind(u64 Address, i32 DebugeePID);
static bool BreakpointEnabled(breakpoint *BP);
static breakpoint BreakpointCreate(u64 Address, i32 DebugeePID);
static void BreakpointEnable(breakpoint *BP);
static void BreakpointDisable(breakpoint *BP);

static address_range AddressRangeCurrentAndNextLine();
static void ImGuiShowRegisters(user_regs_struct Regs);
static size_t PeekDebugeeMemory(size_t Address, i32 DebugeePID);
static void DisassembleAroundAddress(size_t Address, i32 DebugeePID);
static inst_type GetInstructionType(cs_insn *Instruction);
static size_t FindEntryPointAddress();

static bool AddressBetween(size_t Address, size_t Lower, size_t Upper);
static size_t GetRegisterByABINumber(u32 Number);

static bool CharInString(char *String, char C);
static u32 StringCountChar(char *String, char C);
static void StringCopy(char *Dest, char *Src);
static void StringConcat(char *Dest, char *Src);
static bool StringsMatch(char *Str0, char *Str1);
static u64 HexStringToInt(char *String);
static char * DumpFile(char *Path);

static void DebugStart();

#endif //DEBAG_H

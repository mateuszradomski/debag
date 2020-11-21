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
    char Operation[32];
};

struct address_range
{
    size_t Start;
    size_t End;
};

struct src_file
{
    char *Path;
    char *Content;
    u32 LineCount;
};

struct di_src_line
{
    size_t Address;
    u32 LineNum;
    char *Path;
};

struct dwarf_function
{
    char *Name;
    char *FilePath;
    
    size_t LowPC;
    size_t HighPC;
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
};

#define MAX_BREAKPOINT_COUNT 8
breakpoint Breakpoints[MAX_BREAKPOINT_COUNT];
int BreakpointCount = 0;

#define MAX_DISASM_INSTRUCTIONS 31
disasm_inst DisasmInst[MAX_DISASM_INSTRUCTIONS];
int DisasmInstCount = 0;

#define MAX_SOURCE_FILES_FUNCTIONS 8
src_file SourceFiles[MAX_SOURCE_FILES_FUNCTIONS];
int SourceFilesCount = 0;

csh DisAsmHandle;
user_regs_struct Regs;

#define MAX_DW_LINE_TABLE_ENTRIES 256
di_src_line DWLineTable[MAX_DW_LINE_TABLE_ENTRIES];
u32 DWLineEntriesCount = 0;

#define MAX_DW_FUNCTIONS 32
dwarf_function DWFunctions[MAX_DW_FUNCTIONS];
u32 DWFunctionsCount = 0;

#if 0
#define MAX_DISASM_INST_AT_STEP 32
disasm_inst DisasmInstStep[MAX_DISASM_INST_AT_STEP] = {};
u32 DisasmInstStepCount = 0;
#endif

dbg Debuger;

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

static di_src_line *LineTableFindByAddress(size_t Address);
static di_src_line *LineTableFindByLineNum(u32 LineNum);
static void ImGuiShowRegisters(user_regs_struct Regs);
static size_t PeekDebugeeMemory(size_t Address, i32 DebugeePID);
static void DisassembleAroundAddress(size_t Address, i32 DebugeePID);
static void ParseForLineTable(Dwarf_Debug Debug, Dwarf_Die DIE);
static void RecurForEachDIE(Dwarf_Debug Debug, Dwarf_Die DIE, i32 RecurLevel);
static void ReadDwarf();
static size_t SearchDIEsForEntryPoint(Dwarf_Debug Debug, Dwarf_Die DIE, i32 RecurLevel);
static size_t FindEntryPointAddress();
static void DebugStart();

#endif //DEBAG_H

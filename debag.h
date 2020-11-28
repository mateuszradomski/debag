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

// TODO(mateusz): All of this debug information is going to be
// allocated using a linear allocator, which will reduce the memory waste

struct di_src_file
{
    char *Path;
    char *Content;
    u32 LineCount;
};

struct di_src_line
{
    size_t Address;
    u32 LineNum;
    i32 SrcFileIndex;
};

struct di_variable
{
    char Name[64];
    
    size_t TypeOffset;
    u8 LocationAtom;
    ssize_t Offset;
};

struct di_frame_info
{
    Dwarf_Cie *CIEs;
    Dwarf_Signed CIECount;
    Dwarf_Fde *FDEs;
    Dwarf_Signed FDECount;
};

#define MAX_DI_VARIABLES 16

struct di_lexical_scope
{
    // NOTE(mateusz): If RangesCount == 0, then address information is stored
    // in LowPC and HighPC, otherwise, LowPC and HighPC are zeroed and addresses
    // are stores in RangesLowPCs and RangesHighPCs and there are RangesCount of them
    size_t LowPC;
    size_t HighPC;
    size_t RangesLowPCs[8];
    size_t RangesHighPCs[8];
    u32 RangesCount = 0;
    
    di_variable DIVariables[MAX_DI_VARIABLES];
    u32 DIVariablesCount = 0;
};

#define MAX_DI_PARAMETERS 16
#define MAX_DI_LEX_SCOPES 16

struct di_function
{
    char Name[64];
    char FilePath[64];
    
    size_t TypeOffset;
    bool FrameBaseIsCFA;
    di_variable DIParams[MAX_DI_PARAMETERS];
    u32 DIParamsCount = 0;
    di_lexical_scope DIFuncLexScope;
    di_lexical_scope DILexScopes[MAX_DI_LEX_SCOPES];
    u32 DILexScopeCount = 0;
};

enum
{
    DI_COMP_UNIT_NULL = 0x0,
    DI_COMP_UNIT_HAS_RANGES = 0x1,
};

typedef i32 di_compile_unit_flags;

struct di_compile_unit
{
    char Name[128];
    
    size_t LowPC;
    size_t HighPC;
    address_range AddressRanges[8];
    
    di_compile_unit_flags Flags;
};

struct di_base_type
{
    size_t DIEOffset;
    u32 ByteSize;
    u32 Encoding;
};

struct di_typedef
{
    char Name[64];
    size_t DIEOffset;
    size_t ActualTypeOffset;
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

#define MAX_DI_SOURCE_FILES 8
di_src_file *DISourceFiles = 0x0;
u32 DISourceFilesCount = 0;

#define MAX_DI_SOURCE_LINES (1 << 15)
di_src_line *DISourceLines = 0x0;
u32 DISourceLinesCount = 0;

#define MAX_DI_FUNCTIONS 192
di_function *DIFunctions = 0x0;
u32 DIFuctionsCount = 0;

#define MAX_DI_COMPILE_UNITS 16
di_compile_unit *DICompileUnits = 0x0;
u32 DICompileUnitsCount = 0;

#define MAX_DI_BASE_TYPES 24
di_base_type DIBaseTypes[MAX_DI_BASE_TYPES];
u32 DIBaseTypesCount = 0;

#define MAX_DI_TYPEDEFS 128
di_base_type DITypedefs[MAX_DI_TYPEDEFS];
u32 DITypedefsCount = 0;

di_frame_info DIFrameInfo = {};

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

static di_src_line *LineTableFindByAddress(size_t Address);
static di_src_line *LineTableFindByLineNum(u32 LineNum);
static address_range AddressRangeCurrentAndNextLine();
static void ImGuiShowRegisters(user_regs_struct Regs);
static size_t PeekDebugeeMemory(size_t Address, i32 DebugeePID);
static void DisassembleAroundAddress(size_t Address, i32 DebugeePID);
static inst_type GetInstructionType(cs_insn *Instruction);
static size_t FindEntryPointAddress();
static void DebugStart();

#endif //DEBAG_H

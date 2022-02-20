#ifndef DBG_H
#define DBG_H

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
        
        size_t R8;
        size_t R9;
        size_t R10;
        size_t R11;
        size_t R12;
        size_t R13;
        size_t R14;
        size_t R15;
        
        size_t RBP;
        size_t RSP;
        
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

struct logging_switches
{
    bool DwarfLogs;
    bool VarLogs;
    bool MainLogs;
    bool DisasmLogs;
    bool FlowLogs;
    bool LangLogs;
};
struct function_representation;

typedef function_representation* unwind_function;

struct unwind_functions_bucket
{
    unwind_functions_bucket *Next;
    unwind_function Functions[8];
    u32 Count;
};

struct unwind_functions_list
{
    unwind_functions_bucket *Head;
    unwind_functions_bucket *Tail;
    u32 Count;
};

struct debugee_flags
{
    u8 Running  : 1;
    u8 Steped   : 1;
    u8 PIE      : 1;
};

struct unwind_info
{
    size_t Address;
    unwind_functions_list FuncList;
};

struct cpu_registers_flags
{
    u8 HasMMX : 1;
    u8 HasSSE : 1;
    u8 HasAVX : 1;
    // TODO(mateusz): To be supported
    // u8 HasAVX512 : 1;
};

struct cpu_registers_enabled_flags
{
    u8 EnabledMMX : 1;
    u8 EnabledSSE : 1;
    u8 EnabledAVX : 1;
    // TODO(mateusz): To be supported
    // u8 EnabledAVX512 : 1;
};

struct debugee
{
    arena Arena;
    debugee_flags Flags;
    i32 PID;
    char ProgramPath[PATH_MAX];
    size_t LoadAddress;

    x64_registers Regs;
    u8 *XSaveBuffer;
    u32 XSaveSize;
    u32 AVXOffset;
    cpu_registers_enabled_flags RegsFlags;
};

struct dbg
{
    bool InputChange;
    char ProgramArgs[128];
    char PathToRunIn[PATH_MAX];

    void *UnwindRemoteArg;
    unwind_info Unwind;

    cpu_registers_flags RegsFlags;

    logging_switches Log;
};

dbg Debuger;
debugee Debugee;

/*
 * Flow Control for Debugee
 */
static void DebugeeStart();
static void DebugeeKill();
static void DebugeeContinueOrStart();
static void DebugeeRestart();
static void DebugeeWaitForSignal();
static void DebugeeToNextLine(bool StepIntoFunctions);
static void DebugeeStepInstruction();
static void DebugeeToNextInstruction(bool StepIntoFunctions);
static void DebugeeContinueProgram();
static void DebugeeStepOutOfFunction();

/*
 * I/O with Debugee
 */
static x64_registers    DebugeePeekRegisters();
static void             DebugeeSetRegisters(x64_registers Regs);
static size_t           DebugeeGetProgramCounter();
static size_t           DebugeeGetReturnAddress(size_t Address);
static void             DebugeePokeMemory(size_t Address, size_t MachineWord);
static size_t           DebugeePeekMemory(size_t Address);
static void             DebugeePeekMemoryArray(size_t StartAddress, u32 EndAddress, u8 *OutArray, u32 BytesToRead);
static size_t           DebugeeGetLoadAddress(i32 DebugeePID);

/*
 * Caching Debugee information
 */
static void             DebugeeDisassembleAroundAddress(address_range AddrRange);
static void             DebugeeBuildBacktrace();

/*
 * Debuger related functions
 */

static void DebugerUpdateTransient();
static void DebugerDeallocTransient();
static void DebugerMain();

/*
 * Register related functions
 */
static u32              CapstoneRegisterToABINumber(x86_reg Register);
static size_t           RegisterGetByABINumber(x64_registers Registers, u32 Number);
static char *           RegisterGetNameByUnionIndex(u32 Index);
static x64_registers    RegistersFromUSR(user_regs_struct URS);
static user_regs_struct RegistersToUSR(x64_registers Regs);

/*
 * Disassembly related functions
 */
static inst_type        AsmInstructionGetType(cs_insn *Instruction);

#endif

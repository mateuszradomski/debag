#ifndef DBG_H
#define DBG_H

union x64_registers
{
    struct
    {
        size_t RAX, RBX, RCX, RDX, RDI, RSI;
        size_t R8, R9, R10, R11, R12, R13, R14, R15;
        size_t RBP, RSP;
        size_t OrigRax, Cs, Eflags, Ss, FsBase, GsBase, Ds, Es, Fs, Gs;
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
    unwind_functions_bucket *Head, *Tail;
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

/*
 * Flow Control for Debugee
 */
static debugee          DebugeeCreate(debugee *Debugee);
static void             DebugeeStart(debugee *Debugee);
static void             DebugeeKill(debugee *Debugee);
static void             DebugeeContinueOrStart(debugee *Debugee);
static void             DebugeeRestart(debugee *Debugee);
static void             DebugeeWaitForSignal(debugee *Debugee);
static void             DebugeeToNextLine(debugee *Debugee, bool StepIntoFunctions);
static void             DebugeeStepInstruction(debugee *Debugee);
static void             DebugeeToNextInstruction(debugee *Debugee, bool StepIntoFunctions);
static void             DebugeeContinueProgram(debugee *Debugee);
static void             DebugeeStepOutOfFunction(debugee *Debugee);

/*
 * I/O with Debugee
 */
static x64_registers    DebugeePeekRegisters(debugee *Debugee);
static void             DebugeePeekXSave(debugee *Debugee);
static void             DebugeeSetRegisters(debugee *Debugee, x64_registers Regs);
static size_t           DebugeeGetProgramCounter(debugee *Debugee);
static size_t           DebugeeGetReturnAddress(debugee *Debugee, size_t Address);
static void             DebugeePokeMemory(debugee *Debugee, size_t Address, size_t MachineWord);
static size_t           DebugeePeekMemory(debugee *Debugee, size_t Address);
static void             DebugeePeekMemoryArray(debugee *Debugee, size_t StartAddress, u32 EndAddress, u8 *OutArray, u32 BytesToRead);
static size_t           DebugeeGetLoadAddress(debugee *Debugee);

/*
 * Caching Debugee information
 */
static void             DebugeeBuildBacktrace(debugee *Debugee);

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

#endif

/* date = November 18th 2020 7:33 pm */

#ifndef DEBAG_H
#define DEBAG_H

#define DWARF_CALL(x) assert((x) == DW_DLV_OK)

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

debugee Debugee;

#define MAX_BREAKPOINT_COUNT 8
breakpoint *Breakpoints = 0x0;
u32 BreakpointCount = 0;

#define MAX_TEMP_BREAKPOINT_COUNT 32
breakpoint *TempBreakpoints = 0x0;
u32 TempBreakpointsCount = 0;

arena DisasmArena;
disasm_inst *DisasmInst = 0x0;
u32 DisasmInstCount = 0;

csh DisAsmHandle;

button KeyboardButtons[GLFW_KEY_LAST] = {};
keyboard_modifiers KeyMods = {};

#define ARGV_MAX  255
#define ARGV_TOKEN_MAX  255

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

/*
 * Keyboard/mouse and window functions
 */
static void GLFWModsToKeyboardModifiers(int Mods);
static void KeyboardButtonCallback(GLFWwindow *Window, int Key, int Scancode, int Action, int Mods);
static void MousePositionCallback(GLFWwindow *Window, double X, double Y);
static void MouseButtonCallback(GLFWwindow *Window, int Key, int Action, int Mods);
static void WindowSizeCallback(GLFWwindow *Window, i32 Width, i32 Height);
static void ButtonsUpdate(button *Buttons, u32 Count);

/*
 * String functions
 */
static bool     StringHasChar(char *String, char C);
static char *   StringFindLastChar(char *String, char C);
static u32      StringCountChar(char *String, char C);
static void     StringCopy(char *Dest, char *Src);
static void     StringConcat(char *Dest, char *Src);
static bool     StringMatches(char *Str0, char *Str1);
static bool     StringEmpty(char *Str);
static void     StringReplaceChar(char *Str, char Find, char Replace);
static u64      StringHexToInt(char *String);
static u32      StringLength(char *Str);
static char *   StringDuplicate(arena *Arena, char *Str);
static bool     StringStartsWith(char *Str, char *Start);
static u32      StringSplit(char *Str, char Delimiter);
static char *   StringSplitNext(char *Str);
static u32      StringSplitCountStarting(char *Lines, u32 LinesCount, char *Start);
static void     StringToArgv(char *Str, char **ArgvOut, u32 *Argc);

/*
 * File functions
 */ 
static bool     IsFile(char *Path);
static char *   DumpFile(arena *Arena, char *Path);

/*
 * Debugee related functions
 */


/*
 * Breakpoints related functions
 */
static breakpoint * BreakpointFind(size_t Address, breakpoint *BPs, u32 Count);
static breakpoint * BreakpointFind(size_t Address);
static bool         BreakpointEnabled(breakpoint *BP);
static breakpoint   BreakpointCreate(size_t Address);
static breakpoint   BreakpointCreateAttachSourceLine(size_t Address);
static void         BreakpointEnable(breakpoint *BP);
static void         BreakpointDisable(breakpoint *BP);

//static void BreakpointPushAtSourceLine(di_src_file *Src, u32 LineNum, breakpoint *BPs, u32 *Count);

/*
 * Setting breakpoints at places
 */
static bool         BreakAtFunctionName(char *Name);
static void         BreakAtMain();
static bool         BreakAtAddress(char *AddressStr);
static bool         BreakAtAddress(size_t Address);
static void         BreakAtCurcialInstrsInRange(address_range Range, bool BreakCalls, breakpoint *Breakpoints, u32 *BreakpointsCount);

#endif //DEBAG_H

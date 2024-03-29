#include <cstdio>
#include <ctime>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <err.h>
#include <cctype>
#include <linux/limits.h>

#include <cpuid.h>

#include <GLFW/glfw3.h>
#include <capstone/capstone.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>
#include <libelf.h>
#include <libunwind-ptrace.h>

#include <libs/imgui/imgui.h>
#include <libs/imgui/imgui_impl_glfw.h>
#include <libs/imgui/imgui_impl_opengl2.h>

#include "utils.h"
#include "dbg.h"
#include "debag.h"
#include "dwarf.h"
#include "gui.h"
#include "watch_lang.h"
#include "utils.cpp"
#include "dbg.cpp"
#include "dwarf.cpp"
#include "flow.cpp"
#include "gui.cpp"
#include "watch_lang.cpp"

/*
 * A big big TODO list:
 * - When breaking at an function or address we need to have DebugInfo loaded about that file
 * load it dynamicaly when the user asks for a breakpoint at that address before the program
 * is running.
 * - When the program seg faults show a backtrace
 * - Define a rigorous way of being able to restart the program
 * - Big goal is to be able to run the debugger inside the debugger.
 * - hamster_debug
 *   - While in a class/struct/union method you cannot see the variables, because they have no names
 *     the entry for the subprogram is heavily fragmented around the DWARF info
 * - Remove dependency on GLFW
 */

static void
GLFWModsToKeyboardModifiers(int Mods)
{
    KeyMods.Shift    = (Mods & GLFW_MOD_SHIFT) ? 1 : 0;
    KeyMods.Control  = (Mods & GLFW_MOD_CONTROL) ? 1 : 0;
    KeyMods.Alt      = (Mods & GLFW_MOD_ALT) ? 1 : 0;
    KeyMods.Super    = (Mods & GLFW_MOD_SUPER) ? 1 : 0;
    KeyMods.CapsLock = (Mods & GLFW_MOD_CAPS_LOCK) ? 1 : 0;
    KeyMods.NumLock  = (Mods & GLFW_MOD_NUM_LOCK) ? 1 : 0;
}

static void
KeyboardButtonCallback(GLFWwindow *Window, int Key, int Scancode, int Action, int Mods)
{
	assert(Key != GLFW_KEY_UNKNOWN);
    (void)Window; // That is unused.
    (void)Scancode; // That is unused.
    
    GLFWModsToKeyboardModifiers(Mods);
    if(Action == GLFW_PRESS) {
        KeyboardButtons[Key].Down = true;
    } else if(Action == GLFW_REPEAT) {
        KeyboardButtons[Key].Repeat = true;
    } else if(Action == GLFW_RELEASE) {
        KeyboardButtons[Key].Repeat = false;
        KeyboardButtons[Key].Down = false;
    }
    
    Debuger.InputChange = true;
}

static void
MousePositionCallback(GLFWwindow *Window, double X, double Y)
{
    (void)Window;
    (void)X;
    (void)Y;
    
    Debuger.InputChange = true;
}

static void
MouseButtonCallback(GLFWwindow *Window, int Key, int Action, int Mods)
{
    (void)Window;
    (void)Key;
    (void)Action;
    (void)Mods;
    
    Debuger.InputChange = true;
}

static void
WindowSizeCallback(GLFWwindow* Window, i32 Width, i32 Height)
{
    (void)Window;
    
    Gui->WindowWidth = Width;
    Gui->WindowHeight = Height;
}

static void
ButtonsUpdate(button *Buttons, u32 Count)
{
    for(u32 I = 0; I < Count; I++)
    {
        Buttons[I].Pressed = Buttons[I].Down && !Buttons[I].Last;
        Buttons[I].Last = Buttons[I].Down;
    }
}

static bool
StringHasChar(char *String, char C)
{
    while(String && String[0])
    {
        if(String[0] && String[0] == C)
        {
            return true;
        }
        String++;
    }
    
    return false;
}

static char *
StringFindLastChar(char *String, char C)
{
    char *Result = 0;
    
    while(String[0])
    {
        if(String[0] == C)
        {
            Result = String;
        }
        
        String++;
    }
    
    return Result;
}

static u32
StringCountChar(char *String, char C)
{
    u32 Result = 0;
    while(String && *String)
    {
        if(String[0] == C)
        {
            Result += 1;
        }
        String++;
    }
    
    return Result;
}

static void
StringCopy(char *Dest, char *Src)
{
    while(Dest && Src && Src[0])
    {
        Dest[0] = Src[0];
        
        Dest++;
        Src++;
    }
    Dest[0] = '\0';
}

static void
StringConcat(char *Dest, char *Src)
{
    if(Dest && Src)
    {
        while(Dest[0])
        {
            Dest++;
        }
        
        while(Src[0])
        {
            Dest[0] = Src[0];
            Dest++;
            Src++;
        }
    }
}

static bool
StringMatches(char *Str0, char *Str1)
{
    bool Result = true;
    
    if(!Str0 || !Str1)
    {
        Result = false;
        return Result;
    }
    
    while(Str0 && Str0[0] && Str1 && Str1[0])
    {
        if(Str0[0] != Str1[0])
        {
            Result = false;
            break;
        }
        Str0++;
        Str1++;
    }

    if(!(!Str0[0] && !Str1[0]))
    {
        Result = false;
    }
    
    return Result;
}

static bool
StringEmpty(char *Str)
{
    bool Result = false;

    if(!Str || !Str[0])
    {
        Result = true;
    }

    return Result;
}

static void
StringReplaceChar(char *Str, char Find, char Replace)
{
    while(Str && Str[0])
    {
        if(Str[0] == Find)
        {
            Str[0] = Replace;
        }
        
        Str++;
    }
}

static u64
StringHexToInt(char *String)
{
    u64 Result = 0;
    
    while(String[0] && String[0] != 'x')
    {
        String++;
    }
    
    String++;
    
    while(String[0])
    {
        Result *= 16;
        if(String[0] >= '0' && String[0] <= '9')
        {
            Result += String[0] - '0';
        }
        else
        {
            char C = TO_LOWERCASE(String[0]);
            assert(C >= 'a' && C <= 'f');
            
            Result += (C - 'a') + 10;
        }
        
        String++;
    }
    
    return Result;
}

static u32
StringLength(char *Str)
{
    return strlen(Str);
}

static char *
StringDuplicate(arena *Arena, char *Str)
{
    char *Result = 0x0;
    
    u32 Len = StringLength(Str);
    Result = ArrayPush(Arena, char, Len + 1);
    StringCopy(Result, Str);
    
    return Result;
}

static bool
StringStartsWith(char *Str, char *Start)
{
    u32 StrLen = StringLength(Str);
    u32 StartLen = StringLength(Start);
    if(StrLen < StartLen)
    {
        return false;
    }
    
    return strncmp(Str, Start, StartLen) == 0;
}

// NOTE(mateusz): Modifies the string in place, putting null-termination
// in places of the delimiter, returns the amount of elements that you can work on.
static u32
StringSplit(char *Str, char Delimiter)
{
    u32 Parts = 1;
    
    while(*Str)
    {
        if(*Str == Delimiter)
        {
            *Str = '\0';
            Parts++;
        }
        Str++;
    }
    
    return Parts;
}

// NOTE(mateusz): Helper for the string_split function. The user is supposed to
// know that it can safely ask for the next split element.
static char *
StringSplitNext(char *Str)
{
    char *Result = Str + StringLength(Str) + 1;
    
    return Result;
}

static u32
StringSplitCountStarting(char *Lines, u32 LinesCount, char *Start)
{
    u32 Result = 0;
    
    char *Line = Lines;
    for(u32 I = 0; I < LinesCount; I++)
    {
        if(StringStartsWith(Line, Start))
        {
            Result++;
        }
        Line = StringSplitNext(Line);
    }
    
    return Result;
}

#define ARGV_MAX  255
#define ARGV_TOKEN_MAX  255

static void
StringToArgv(char *Str, char **ArgvOut, u32 *Argc)
{
    bool InToken = false;
    bool InContainer = false;
    bool Escaped = false;
    char ContainerStart = 0;
    
    char *Token = (char *)calloc(ARGV_TOKEN_MAX, sizeof(char));
    assert(Token);
    
    u32 StrLen = StringLength(Str);
    for(u32 I = 0; I < StrLen; I++)
    {
        char C = Str[I];
        
        switch (C)
        {
            /* Handle whitespace */
            case ' ':
            case '\t':
            case '\n':
            {
                if (!InToken)
                {
                    continue;
                }
                
                if (InContainer)
                {
                    int Idx = StringLength(Token);
                    assert(Idx < ARGV_TOKEN_MAX);
                    
                    Token[Idx] = C;
                    continue;
                }
                
                if(Escaped)
                {
                    Escaped = false;
                    int Idx = StringLength(Token);
                    assert(Idx < ARGV_TOKEN_MAX);
                    
                    Token[Idx] = C;
                    continue;
                }
                
                /* if reached here, we're at end of token */
                InToken = false;
                assert(*Argc < ARGV_MAX);
                
                ArgvOut[(*Argc)++] = Token;
                Token = (char *)calloc(ARGV_TOKEN_MAX, sizeof(char));
            }break;
            /* Handle quotes */
            case '\'':
            case '\"':
            {
                
                if(Escaped)
                {
                    int Idx = StringLength(Token);
                    assert(Idx < ARGV_TOKEN_MAX);
                    
                    Token[Idx] = C;
                    Escaped = false;
                    continue;
                }
                
                if(!InToken)
                {
                    InToken = true;
                    InContainer = true;
                    ContainerStart = C;
                    continue;
                }
                
                if(InContainer)
                {
                    if(C == ContainerStart)
                    {
                        InContainer = false;
                        InToken = false;
                        assert(*Argc < ARGV_MAX);
                        
                        ArgvOut[(*Argc)++] = Token;
                        Token = (char *)calloc(ARGV_TOKEN_MAX, sizeof(char));
                        continue;
                    }
                    else 
                    {
                        int Idx = StringLength(Token);
                        assert(Idx < ARGV_TOKEN_MAX);
                        
                        Token[Idx] = C;
                        continue;
                    }
                }
                
                /* XXX in this case, we:
                 *    1. have a quote
                 *    2. are in a token
                 *    3. and not in a container
                 * e.g.
                 *    hell"o
                 *
                 * what's done here appears shell-dependent,
                 * but overall, it's an error.... i *think*
                 */
                assert(!"Parse Error! Bad quotes\n");
            }break;
            case '\\':
            {
                if(InContainer && Str[I+1] != ContainerStart)
                {
                    int Idx = StringLength(Token);
                    assert(Idx < ARGV_TOKEN_MAX);
                    
                    Token[Idx] = C;
                    continue;
                }
                if(Escaped)
                {
                    int Idx = StringLength(Token);
                    assert(Idx < ARGV_TOKEN_MAX);
                    
                    Token[Idx] = C;
                    continue;
                }
                
                Escaped = true;
            }break;
            default:
            {
                if (!InToken) {
                    InToken = true;
                }
                
                int Idx = StringLength(Token);
                assert(Idx < ARGV_TOKEN_MAX);
                
                Token[Idx] = C;
            }break;
        }
    }
    
    assert(!InContainer);
    assert(!Escaped);
    assert(Token);
    if(strlen(Token) != 0)
    {
        assert(*Argc < ARGV_MAX);
        
        ArgvOut[(*Argc)++] = Token;
    }
}

static u32
CapstoneRegisterToABINumber(x86_reg Register)
{
    u32 Result = 0;

    switch(Register)
    {
    case X86_REG_RAX:
        Result = 0;
        break;
    case X86_REG_RDX:
        Result = 1;
        break;
    case X86_REG_RCX:
        Result = 2;
        break;
    case X86_REG_RBX:
        Result = 3;
        break;
    case X86_REG_RSI:
        Result = 4;
        break;
    case X86_REG_RDI:
        Result = 5;
        break;
    case X86_REG_RBP:
        Result = 6;
        break;
    case X86_REG_RSP:
        Result = 7;
        break;
    case X86_REG_R8:
        Result = 8;
        break;
    case X86_REG_R9:
        Result = 9;
        break;
    case X86_REG_R10:
        Result = 10;
        break;
    case X86_REG_R11:
        Result = 11;
        break;
    case X86_REG_R12:
        Result = 12;
        break;
    case X86_REG_R13:
        Result = 13;
        break;
    case X86_REG_R14:
        Result = 14;
        break;
    case X86_REG_R15:
        Result = 15;
        break;
    default:
        assert(false && "Unhandled ABI register");
    };

    return Result;
}

static x64_registers
RegistersFromUSR(user_regs_struct URS)
{
    x64_registers Result = {};
    
    Result.R15 = URS.r15;
    Result.R14 = URS.r14;
    Result.R13 = URS.r13;
    Result.R12 = URS.r12;
    Result.RBP = URS.rbp;
    Result.RBX = URS.rbx;
    Result.R11 = URS.r11;
    Result.R10 = URS.r10;
    Result.R9 = URS.r9;
    Result.R8 = URS.r8;
    Result.RAX = URS.rax;
    Result.RCX = URS.rcx;
    Result.RDX = URS.rdx;
    Result.RSI = URS.rsi;
    Result.RDI = URS.rdi;
    Result.OrigRax = URS.orig_rax;
    Result.RIP = URS.rip;
    Result.Cs = URS.cs;
    Result.Eflags = URS.eflags;
    Result.RSP = URS.rsp;
    Result.Ss = URS.ss;
    Result.FsBase = URS.fs_base;
    Result.GsBase = URS.gs_base;
    Result.Ds = URS.ds;
    Result.Es = URS.es;
    Result.Fs = URS.fs;
    Result.Gs = URS.gs;
    
    return Result;
}

static user_regs_struct
RegistersToUSR(x64_registers Regs)
{
    user_regs_struct Result = {};
    
    Result.r15 = Regs.R15;
    Result.r14 = Regs.R14;
    Result.r13 = Regs.R13;
    Result.r12 = Regs.R12;
    Result.rbp = Regs.RBP;
    Result.rbx = Regs.RBX;
    Result.r11 = Regs.R11;
    Result.r10 = Regs.R10;
    Result.r9 = Regs.R9;
    Result.r8 = Regs.R8;
    Result.rax = Regs.RAX;
    Result.rcx = Regs.RCX;
    Result.rdx = Regs.RDX;
    Result.rsi = Regs.RSI;
    Result.rdi = Regs.RDI;
    Result.orig_rax = Regs.OrigRax;
    Result.rip = Regs.RIP;
    Result.cs = Regs.Cs;
    Result.eflags = Regs.Eflags;
    Result.rsp = Regs.RSP;
    Result.ss = Regs.Ss;
    Result.fs_base = Regs.FsBase;
    Result.gs_base = Regs.GsBase;
    Result.ds = Regs.Ds;
    Result.es = Regs.Es;
    Result.fs = Regs.Fs;
    Result.gs = Regs.Gs;

    return Result;
}

static size_t
RegisterGetByABINumber(x64_registers Registers, u32 Number)
{
    switch(Number)
    {
        case 0:
        return Registers.RAX;
        case 1:
        return Registers.RDX;
        case 2:
        return Registers.RCX;
        case 3:
        return Registers.RBX;
        case 4:
        return Registers.RSI;
        case 5:
        return Registers.RDI;
        case 6:
        return Registers.RBP;
        case 7:
        return Registers.RSP;
        case 8:
        return Registers.R8;
        case 9:
        return Registers.R9;
        case 10:
        return Registers.R10;
        case 11:
        return Registers.R11;
        case 12:
        return Registers.R12;
        case 13:
        return Registers.R13;
        case 14:
        return Registers.R14;
        case 15:
        return Registers.R15;
        default:
        {
            assert(false);
        }break;
    }
}

static char *
RegisterGetNameByUnionIndex(u32 Index)
{
    char *Names[] = {
        "RAX", "RBX", "RCX", "RDX", "RDI", "RSI",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
        "RBP", "RSP",
        "OrigRax", "Cs", "Eflags", "Ss", "FsBase", "GsBase", "Ds", "Es", "Fs", "Gs",
    };
    
    return Names[Index];
}

static inst_type
AsmInstructionGetType(cs_insn *Instruction)
{
    inst_type Result = 0;
    
    if(Instruction->detail)
    {
        for(i32 GroupIndex = 0;
            GroupIndex < Instruction->detail->groups_count;
            GroupIndex++)
        {
            switch(Instruction->detail->groups[GroupIndex])
            {
                case X86_GRP_JUMP:
                {
                    Result |= INST_TYPE_JUMP;
                }break;
                case X86_GRP_CALL:
                {
                    Result |= INST_TYPE_CALL;
                }break;
                case X86_GRP_RET:
                {
                    Result |= INST_TYPE_RET;
                }break;
                // case X86_GRP_BRANCH_RELATIVE:
                // {
                //     Result |= INST_TYPE_RELATIVE_BRANCH;
                // }break;
            }
        }
    }
    
    return Result;
}

static bool
IsFile(char *Path)
{
    return access(Path, F_OK) == 0;
}

static char *
DumpFile(arena *Arena, char *Path)
{
    FILE *FHandle = fopen(Path, "r");
    assert(FHandle);
    fseek(FHandle, 0, SEEK_END);
    u32 FileSize = ftell(FHandle);
    fseek(FHandle, 0, SEEK_SET);
    
    char *Result = ArrayPush(Arena, char, FileSize + 1);
    fread(Result, FileSize, 1, FHandle);
    Result[FileSize] = '\0';
    
    return Result;
}

static void
DebagMain()
{
    GuiInit();
    DisasmArena = ArenaCreateZeros(Kilobytes(256));
    Breakpoints = (breakpoint *)calloc(MAX_BREAKPOINT_COUNT, sizeof(breakpoint));
    TempBreakpoints = (breakpoint *)calloc(MAX_TEMP_BREAKPOINT_COUNT, sizeof(breakpoint));

    Debuger = DebugerCreate();
    Debugee = DebugeeCreate();
    
    glfwInit();
    GLFWwindow *Window = glfwCreateWindow(Gui->WindowWidth, Gui->WindowHeight, "debag", NULL, NULL);
    glfwMakeContextCurrent(Window);
    
    glfwSetKeyCallback(Window, KeyboardButtonCallback);
    glfwSetInputMode(Window, GLFW_LOCK_KEY_MODS, GLFW_TRUE);
    glfwSetMouseButtonCallback(Window, MouseButtonCallback);
    glfwSetCursorPosCallback(Window, MousePositionCallback);
    glfwSetWindowSizeCallback(Window, WindowSizeCallback);
    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& IO = ImGui::GetIO(); (void)IO;

    ImGui_ImplGlfw_InitForOpenGL(Window, true);
    ImGui_ImplOpenGL2_Init();

    ImFontConfig FontConfig = {};
    FontConfig.SizePixels = 16;
    FontConfig.OversampleH = FontConfig.OversampleV = 1;
    FontConfig.PixelSnapH = true;
    Gui->BiggerFont = IO.Fonts->AddFontDefault(&FontConfig);

    ImGui::StyleColorsDark();
    
    // Make windows square not round
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    GuiCreateBreakpointTexture();
    Gui->SpacesArray[0] = "";
    Gui->SpacesArray[1] = " ";
    Gui->SpacesArray[2] = "  ";
    Gui->SpacesArray[3] = "   ";
    Gui->SpacesArray[4] = "    ";
    Gui->SpacesArray[5] = "     ";
    Gui->SpacesArray[6] = "      ";
    Gui->SpacesArray[7] = "       ";
    Gui->SpacesArray[8] = "        ";
    Gui->SpacesArray[9] = "         ";
    
    glClearColor(0.5f, 0.5f, 0.5f, 1.0f);

    ImGuiInputTextFlags ITFlags = 0;
    ITFlags |= ImGuiInputTextFlags_EnterReturnsTrue;
    
    ImGuiTabBarFlags TBFlags = ImGuiTabBarFlags_Reorderable;
    TBFlags |= ImGuiTabBarFlags_FittingPolicyResizeDown;
    TBFlags |= ImGuiTabBarFlags_FittingPolicyScroll;
    
    ImGuiWindowFlags WinFlags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse;
    
    assert(cs_open(CS_ARCH_X86, CS_MODE_64, &DisAsmHandle) == CS_ERR_OK);
    //cs_option(DisAsmHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); 
    cs_option(DisAsmHandle, CS_OPT_DETAIL, CS_OPT_ON);

    bool CenteredDissassembly = false;
    bool CenteredSourceCode = false;
    
    while(!glfwWindowShouldClose(Window))
    {
        //if(!Debuger.InputChange) { goto EndDraw; }
        //else { Debuger.InputChange = false; }
        
        // NOTE(mateusz): This has to happen before the calls to next lines
        if(Debugee.Flags.Steped)
        {
            if(CenteredDissassembly && CenteredSourceCode)
            {
                Debugee.Flags.Steped = !Debugee.Flags.Steped;
                CenteredDissassembly = false;
                CenteredSourceCode = false;
            }
        }
        
        glClear(GL_COLOR_BUFFER_BIT);
        
        GuiStartFrame();
        
        f64 MenuBarHeight = 0.0;
        bool BreakAtFunction = false;
        bool BreakAtAddress = false;
        if (ImGui::BeginMainMenuBar())
        {
            auto MenuBarSize = ImGui::GetWindowSize();
            MenuBarHeight = MenuBarSize.y;
            bool IsRunning = Debugee.Flags.Running;
            
            if(ImGui::BeginMenu("File"))
            {
                f32 OneThird = 0.3333333f;
                ImGui::PushItemWidth(Gui->WindowWidth * OneThird);
                ImGui::InputText("Program path", Debugee.ProgramPath, sizeof(Debugee.ProgramPath));
                ImGui::InputText("Program args", Debuger.ProgramArgs, sizeof(Debuger.ProgramArgs));
                ImGui::InputText("Working directory", Debuger.PathToRunIn, sizeof(Debuger.PathToRunIn));
                ImGui::PopItemWidth();

                ImGui::Separator();

                if(ImGui::MenuItem("Open new file", "Ctrl+P", false, IsRunning))
                {
                    GuiShowOpenFile();
                }
                
                ImGui::EndMenu();
            }
            if(ImGui::BeginMenu("Control"))
            {
                if(ImGui::MenuItem("Start process", "F5", false, !IsRunning))
                {
                    DebugeeContinueOrStart(&Debugee);
                }
                if(ImGui::MenuItem("Restart process", "Shift+F5", false, IsRunning))
                {
                    DebugeeRestart(&Debugee);
                }
                
                ImGui::Separator();
                
                if(ImGui::MenuItem("Continue", "F5", false, IsRunning))
                {
                    DebugeeContinueOrStart(&Debugee);
                }
                if(ImGui::MenuItem("Step out", "F9", false, IsRunning))
                {
                    DebugeeStepOutOfFunction(&Debugee);
                    DebugerUpdateTransient(&Debuger);
                }
                if(ImGui::MenuItem("Step next", "F10", false, IsRunning))
                {
                    DebugeeToNextLine(&Debugee, false);
                    DebugerUpdateTransient(&Debuger);
                }
                if(ImGui::MenuItem("Step in", "F11", false, IsRunning))
                {
                    DebugeeToNextLine(&Debugee, true);
                    DebugerUpdateTransient(&Debuger);
                }
                if(ImGui::MenuItem("Next instruction", "Shift+F10", false, IsRunning))
                {
                    DebugeeToNextInstruction(&Debugee, false);
                    DebugerUpdateTransient(&Debuger);
                }
                if(ImGui::MenuItem("Step instruction", "Shift+F11", false, IsRunning))
                {
                    DebugeeToNextInstruction(&Debugee, true);
                    DebugerUpdateTransient(&Debuger);
                }
                
                ImGui::Separator();
                
                if(ImGui::MenuItem("Break at function", "Ctrl+b", false, IsRunning))
                {
                    BreakAtFunction = true;
                }
                
                if (ImGui::MenuItem("Break at address", "Ctrl+B", false, IsRunning))
                {
                    BreakAtAddress = true;
                }
                
                ImGui::EndMenu();
            }
            if(ImGui::BeginMenu("Help"))
            {
                ImGui::TextUnformatted("Debag is a C/C++ GUI debugger for Linux");
                ImGui::TextUnformatted("created by Mateusz Radomski.");
                
                ImGui::EndMenu();
            }
#ifdef DEBUG
            if(ImGui::BeginMenu("Debug"))
            {
                char *Labels[] = {
                    "Show Dwarf Logs",
                    "Show Var Logs",
                    "Show Main Logs",
                    "Show Disasm Logs",
                    "Show Flow Logs",
                };

                bool *Logs = (bool *)&Debuger.Log;
                for(u32 I = 0; I < ARRAY_LENGTH(Labels); I++)
                {
                    ImGui::Checkbox(Labels[I], &Logs[I]);
                }

                ImGui::EndMenu();
            }
#endif

            ImGui::Text("(%.1f FPS)", ImGui::GetIO().Framerate);
            
            if(Gui->StatusText)
            {
                auto StatusColor = ImVec4(1.0f, 1.0f, 0.0f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Button, StatusColor);
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, StatusColor);
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, StatusColor);
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 0.0f, 0.0f, 1.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0, 0));
                
                ImGui::Button(Gui->StatusText, ImVec2(Gui->WindowWidth, 0));
                
                ImGui::PopStyleVar(1);
                ImGui::PopStyleColor(4);
            }
            
            ImGui::EndMainMenuBar();
        }
        
        if(KeyboardButtons[GLFW_KEY_F5].Pressed)
        {
            if(KeyMods.Shift)
            {
                DebugeeRestart(&Debugee);
            }
            else
            {
                DebugeeContinueOrStart(&Debugee);
            }
        }

        if(Debugee.Flags.Running)
        {
            bool F9 = KeyboardButtons[GLFW_KEY_F9].Pressed || KeyboardButtons[GLFW_KEY_F9].Repeat;
            
            if(F9)
            {
                DebugeeStepOutOfFunction(&Debugee);
                DebugerUpdateTransient(&Debuger);
            }
        }
        
        if(Debugee.Flags.Running)
        {
            bool F10 = KeyboardButtons[GLFW_KEY_F10].Pressed || KeyboardButtons[GLFW_KEY_F10].Repeat;
            bool F11 = KeyboardButtons[GLFW_KEY_F11].Pressed || KeyboardButtons[GLFW_KEY_F11].Repeat;
            
            if(KeyMods.Shift)
            {
                if(F10)
                {
                    DebugeeToNextInstruction(&Debugee, false);
                    DebugerUpdateTransient(&Debuger);
                }
                if(F11)
                {
                    DebugeeToNextInstruction(&Debugee, true);
                    DebugerUpdateTransient(&Debuger);
                }
            }
            else
            {
                if(F10)
                {
                    DebugeeToNextLine(&Debugee, false);
                    DebugerUpdateTransient(&Debuger);
                }
                if(F11)
                {
                    DebugeeToNextLine(&Debugee, true);
                    DebugerUpdateTransient(&Debuger);
                }
            }
            
            bool Ctrlb = KeyboardButtons[GLFW_KEY_B].Pressed && KeyMods.Control;
            
            if(Ctrlb)
            {
                if(KeyMods.Shift || KeyMods.CapsLock)
                {
                    GuiShowBreakAtAddress();
                }
                else
                {
                    GuiShowBreakAtFunction();
                }
            }

            bool Ctrlp = KeyboardButtons[GLFW_KEY_P].Pressed && KeyMods.Control;

            if(Ctrlp)
            {
                GuiShowOpenFile();
            }
        }

        if(BreakAtFunction)
        {
            GuiShowBreakAtFunction();
        }
        if(BreakAtAddress)
        {
            GuiShowBreakAtAddress();
        }

        if(Gui->ModalFuncShow)
        {
            Gui->ModalFuncShow();
        }

        ImGui::Begin("Disassembly", 0x0, WinFlags);

        ImGui::SetWindowPos(ImVec2(Gui->WindowWidth / 2, MenuBarHeight));
        ImGui::SetWindowSize(ImVec2(Gui->WindowWidth / 2, (Gui->WindowHeight / 3) * 2 - MenuBarHeight));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));

        if(Debugee.Flags.Running)
        {
            ImGuiListClipper Clipper = {};
            Clipper.Begin(DisasmInstCount);
            size_t PC = DebugeeGetProgramCounter(&Debugee);

            // @Speed: Binary search will like this one!
            i32 PCItemIndex = -1;
            for(u32 I = 0; I < DisasmInstCount; I++)
            {
                if(DisasmInst[I].Address == PC)
                {
                    PCItemIndex = I;
                    break;
                }
            }

            if(Debugee.Flags.Steped && PCItemIndex != -1)
            {
                f32 Max = ImGui::GetScrollMaxY();
                f32 Curr = ((f32)PCItemIndex / (f32)DisasmInstCount);
                Curr *= Max;

                ImGui::SetScrollY(Curr);
            }

            while(Clipper.Step())
            {
                for(int I = Clipper.DisplayStart; I < Clipper.DisplayEnd; I++)
                {
                    disasm_inst *Inst = &DisasmInst[I];
                    u32 BaseMnemonicLength = 3; // The shortest mnenomic is of lenght 3
                    u32 MnenomicLengthDiff = StringLength(Inst->Mnemonic) - BaseMnemonicLength;
                    char *Spaces = Gui->SpacesArray[8 - MnenomicLengthDiff];
                
                    if(Inst->Address == PC)
                    {
                        ImGui::TextColored(CurrentLineColor,
                                           "0x%" PRIx64 ":\t%s%s%s\n",
                                           Inst->Address, Inst->Mnemonic, Spaces, Inst->Operation);
                    
                        if(Debugee.Flags.Steped)
                        {
                            ImGui::SetScrollHereY(0.5f);
                            CenteredDissassembly = true;
                        }
                    }
                    else
                    {
                        ImGui::Text("0x%" PRIx64 ":\t%s%s%s\n",
                                    Inst->Address, Inst->Mnemonic, Spaces, Inst->Operation);
                    }
                }
            }
        }

        ImGui::PopStyleVar();
        ImGui::End();

        ImGui::Begin("Listings", 0x0, WinFlags);
        ImGui::SetWindowPos(ImVec2(0, MenuBarHeight));
        ImGui::SetWindowSize(ImVec2(Gui->WindowWidth / 2, (Gui->WindowHeight / 3) * 2 - MenuBarHeight));
        
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
        
        if(Debugee.Flags.Running &&
           ImGui::BeginTabBar("Source lines", TBFlags | ImGuiTabBarFlags_AutoSelectNewTabs))
        {
            di_src_line *Line = DwarfFindLineByAddress(DebugeeGetProgramCounter(&Debugee));

            for(u32 SrcFileIndex = 0; SrcFileIndex < DI->SourceFilesCount; SrcFileIndex++)
            {
                ImGuiTabItemFlags TIFlags = ImGuiTabItemFlags_None;
                if(Line && SrcFileIndex == Line->SrcFileIndex && Debugee.Flags.Steped)
                {
                    TIFlags = ImGuiTabItemFlags_SetSelected;
                }

                char *FileName = StringFindLastChar(DI->SourceFiles[SrcFileIndex].Path, '/') + 1;
                LOG_MAIN("Filename = %s, Path = %s\n", FileName, DI->SourceFiles[SrcFileIndex].Path);

                if(ImGui::BeginTabItem(FileName, NULL, TIFlags))
                {
                    LOG_MAIN("child on %u\n", SrcFileIndex);
                    ImGui::BeginChild("srcfile");

                    di_src_file *Src = &DI->SourceFiles[SrcFileIndex];
                    di_src_line *DrawingLine = 0x0;
                    ImGuiListClipper Clipper = {};
                    Clipper.Begin(Src->ContentLineCount);

                    if(Debugee.Flags.Steped)
                    {
                        if(Line && Src)
                        {
                            f32 Max = ImGui::GetScrollMaxY();
                            f32 Curr = ((f32)Line->LineNum / (f32)Src->ContentLineCount);
                            Curr *= Max;
                            
                            ImGui::SetScrollY(Curr);
                        }
                    }

                    while(Clipper.Step())
                    {
                        for(i32 I = Clipper.DisplayStart; I < Clipper.DisplayEnd; I++)
                        {
                            u32 LineNum = I + 1;
                            char *Spaces = 0x0;
                            if(LineNum >= 1 && LineNum < 10)
                            {
                                Spaces = "     ";
                            }
                            else if(LineNum >= 10 && LineNum < 100)
                            {
                                Spaces = "    ";
                            }
                            else if(LineNum >= 100 && LineNum < 1000)
                            {
                                Spaces = "   ";
                            }
                            else if(LineNum >= 1000 && LineNum < 10000)
                            {
                                Spaces = "  ";
                            }
                            else if(LineNum >= 10000 && LineNum < 100000)
                            {
                                Spaces = " ";
                            }
                            else
                            {
                                assert(false && "A file with over 100k lines? please...");
                            }

                            bool LineHasBreakpoint = false;
                            DrawingLine = DwarfFindLineByNumber(I + 1, SrcFileIndex);
                            breakpoint *BP = 0x0;
                            if(DrawingLine && (BP = BreakpointFind(DrawingLine->Address)) && BreakpointEnabled(BP))
                            {
                                LineHasBreakpoint = true;
                            }

                            ImGui::PushID(I);

                            auto Font = ImGui::GetFont();
                            auto Texture = LineHasBreakpoint ? Gui->BreakpointTextureActive : Gui->BreakpointTextureBlank;
                            ImVec2 ButtonSize = ImVec2(Font->FontSize, Font->FontSize);
                            ImVec2 UV0 = ImVec2(0.0f, 0.0f);
                            ImVec2 UV1 = ImVec2(1.0f, 1.0f);
                            ImVec4 BGColor = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
                            ImVec4 TintColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);

                            bool Button = ImGui::ImageButton(Texture, ButtonSize,
                                                             UV0, UV1, 0, BGColor, TintColor);
                            ImGui::SameLine();

                            ImGui::PopID();

                            // NOTE(mateusz): Lines are indexed from 1
                            if(Line && SrcFileIndex == Line->SrcFileIndex && Line->LineNum == LineNum)
                            {
                                DrawingLine = Line;
                                ImGui::TextColored(CurrentLineColor, "%d%s%s", LineNum, Spaces, Src->Content[I]);
                                if(Debugee.Flags.Steped)
                                {
                                    ImGui::SetScrollHereY(0.5f);
                                    CenteredSourceCode = true;
                                }
                            }
                            else
                            {
                                ImGui::Text("%d%s%s", LineNum, Spaces, Src->Content[I]);
                            }

                            if(Button && DrawingLine)
                            {
                                if(BreakpointEnabled(BP))
                                {
                                    BreakpointDisable(BP);
                                }
                                else
                                {
                                    if(BP)
                                    {
                                        BreakpointEnable(BP);
                                    }
                                    else
                                    {
                                        BreakpointPushAtSourceLine(Src, DrawingLine->LineNum,
                                            Breakpoints, &BreakpointCount);
                                    }
                                }
                            }
                        }
                    }

                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }
            }

            ImGui::EndTabBar();
        }
        
        ImGui::PopStyleVar();
        ImGui::End();
        
        ImGui::Begin("Control panel", 0x0, WinFlags);
        
        ImGui::SetWindowPos(ImVec2(0, (Gui->WindowHeight / 3) * 2));
        ImGui::SetWindowSize(ImVec2(Gui->WindowWidth, Gui->WindowHeight / 3));
        
        if(ImGui::BeginTabBar("Vars", TBFlags))
        {
            if(ImGui::BeginTabItem("Locals"))
            {
                if(Debugee.Flags.Running)
                {
                    ImGui::BeginChild("locals");
                    GuiShowVariables();
                    ImGui::EndChild();
                }
                
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Watch"))
            {
                if(Debugee.Flags.Running)
                {
                    ImGui::BeginChild("watch");
                    GuiShowWatch();
                    ImGui::EndChild();
                }

                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Backtrace"))
            {
                if(Debugee.Flags.Running)
                {
                    ImGui::BeginChild("regs");
                    GuiShowBacktrace();
                    ImGui::EndChild();                    
                }
                
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("x64 Registers"))
            {
                if(Debugee.Flags.Running)
                {
                    ImGui::BeginChild("regs");
                    GuiShowRegisters(Debugee.Regs);
                    ImGui::EndChild();
                }
                
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Breakpoints"))
            {
                if(Debugee.Flags.Running)
                {
                    ImGui::BeginChild("bps");
                    GuiShowBreakpoints();
                    ImGui::EndChild();
                }
                
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        
        ImGui::End();
        
        GuiEndFrame();
        //EndDraw:;
        ButtonsUpdate(KeyboardButtons, (sizeof(KeyboardButtons)/sizeof(KeyboardButtons[0])));
        glfwPollEvents();
        glfwSwapBuffers(Window);
    }

    DwarfCloseSymbolsHandle(&DI->DwarfFd, &DI->Debug);
    DwarfCloseSymbolsHandle(&DI->CFAFd, &DI->CFADebug);
    ImGui::DestroyContext();
    glfwTerminate();
}


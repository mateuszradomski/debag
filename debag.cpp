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
#include <fcntl.h>

#include <GL/glew.h>
#include <GLFW/glfw3.h>
#include <capstone/capstone.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include <libs/imgui/imgui.h>
#include <libs/imgui/imgui_impl_glfw.h>
#include <libs/imgui/imgui_impl_opengl3.h>

#include "debag.h"
#include "dwarf.h"
#include "dwarf.cpp"
#include "flow.cpp"

static void
KeyboardButtonCallback(GLFWwindow *Window, int Key, int Scancode, int Action, int Mods)
{
	assert(Key != GLFW_KEY_UNKNOWN);
    (void)Window; // That is unused.
    (void)Mods; // NOTE(mateusz): I guess we would use it somewhere??
    (void)Scancode; // That is unused.
    
    if(Action == GLFW_PRESS) {
        KeyboardButtons[Key].Down = true;
    } else if(Action == GLFW_RELEASE) {
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
ButtonsUpdate(button *Buttons, u32 Count)
{
    for(u32 I = 0; I < Count; I++)
    {
        Buttons[I].Pressed = Buttons[I].Down && !Buttons[I].Last;
        Buttons[I].Last = Buttons[I].Down;
    }
}

static void
ImGuiStartFrame()
{
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
}

static void
ImGuiEndFrame()
{
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
}

static bool
CharInString(char *String, char C)
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

static bool
StringsMatch(char *Str0, char *Str1)
{
    bool Result = true;
    
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
    
    return Result;
}

static u64
HexStringToInt(char *String)
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

static arena *
ArenaCreate(size_t Size)
{
    arena *Result = (arena *)malloc(sizeof(arena));
    
    Result->BasePtr = (u8 *)malloc(Size);
    Result->CursorPtr = Result->BasePtr;
    Result->Size = Size;
    
    return Result;
}

static void
ArenaDestroy(arena *Arena)
{
    if(Arena)
    {
        free(Arena->BasePtr);
    }
}

static void *
ArenaPush(arena *Arena, size_t Size)
{
    void *Result = 0x0;
    if(Arena)
    {
        size_t BytesLeft = Arena->Size - (size_t)(Arena->CursorPtr - Arena->BasePtr);
        if(Size <= BytesLeft)
        {
            Result = Arena->CursorPtr;
            Arena->CursorPtr += Size;
        }
        else
        {
            printf("%lu\n", (size_t)(Arena->CursorPtr - Arena->BasePtr));
            assert(false);
        }
    }
    
    return Result;
}

static inline bool
AddressBetween(size_t Address, size_t Lower, size_t Upper)
{
    bool Result = false;
    
    Result = (Address >= Lower) && (Address <= Upper);
    
    return Result;
}

static user_regs_struct
PeekRegisters(i32 DebugeePID)
{
    user_regs_struct Result = {};
    
    ptrace(PTRACE_GETREGS, DebugeePID, 0x0, &Result);
    
    return Result;
}

static void
SetRegisters(user_regs_struct Regs, i32 DebugeePID)
{
    ptrace(PTRACE_SETREGS, DebugeePID, 0x0, &Regs);
}

static size_t
GetRegisterByABINumber(u32 Number)
{
    switch(Number)
    {
        case 0:
        return Regs.rax;
        case 1:
        return Regs.rdx;
        case 2:
        return Regs.rcx;
        case 3:
        return Regs.rbx;
        case 4:
        return Regs.rsi;
        case 5:
        return Regs.rdi;
        case 6:
        return Regs.rbp;
        case 7:
        return Regs.rsp;
        case 8:
        return Regs.r8;
        case 9:
        return Regs.r9;
        case 10:
        return Regs.r10;
        case 11:
        return Regs.r11;
        case 12:
        return Regs.r12;
        case 13:
        return Regs.r13;
        case 14:
        return Regs.r14;
        case 15:
        return Regs.r15;
        default:
        {
            assert(false);
        }break;
    }
}

static void
ImGuiShowRegisters(user_regs_struct Regs)
{
    ImGui::Columns(4, 0x0, true);
    
    ImGui::Text("r15: %lX", (u64)Regs.r15);
    ImGui::NextColumn();
    ImGui::Text("r14: %lX", (u64)Regs.r14);
    ImGui::NextColumn();
    ImGui::Text("r13: %lX", (u64)Regs.r13);
    ImGui::NextColumn();
    ImGui::Text("r12: %lX", (u64)Regs.r12);
    ImGui::NextColumn();
    ImGui::Text("rbp: %lX", (u64)Regs.rbp);
    ImGui::NextColumn();
    ImGui::Text("rbx: %lX", (u64)Regs.rbx);
    ImGui::NextColumn();
    ImGui::Text("r11: %lX", (u64)Regs.r11);
    ImGui::NextColumn();
    ImGui::Text("r10: %lX", (u64)Regs.r10);
    ImGui::NextColumn();
    ImGui::Text("r9: %lX", (u64)Regs.r9);
    ImGui::NextColumn();
    ImGui::Text("r8: %lX", (u64)Regs.r8);
    ImGui::NextColumn();
    ImGui::Text("rax: %lX", (u64)Regs.rax);
    ImGui::NextColumn();
    ImGui::Text("rcx: %lX", (u64)Regs.rcx);
    ImGui::NextColumn();
    ImGui::Text("rdx: %lX", (u64)Regs.rdx);
    ImGui::NextColumn();
    ImGui::Text("rsi: %lX", (u64)Regs.rsi);
    ImGui::NextColumn();
    ImGui::Text("rdi: %lX", (u64)Regs.rdi);
    ImGui::NextColumn();
    ImGui::Text("orig_rax: %lX", (u64)Regs.orig_rax);
    ImGui::NextColumn();
    ImGui::Text("rip: %lX", (u64)Regs.rip);
    ImGui::NextColumn();
    ImGui::Text("cs: %lX", (u64)Regs.cs);
    ImGui::NextColumn();
    ImGui::Text("eflags: %lX", (u64)Regs.eflags);
    ImGui::NextColumn();
    ImGui::Text("rsp: %lX", (u64)Regs.rsp);
    ImGui::NextColumn();
    ImGui::Text("ss: %lX", (u64)Regs.ss);
    ImGui::NextColumn();
    ImGui::Text("fs_base: %lX", (u64)Regs.fs_base);
    ImGui::NextColumn();
    ImGui::Text("gs_base: %lX", (u64)Regs.gs_base);
    ImGui::NextColumn();
    ImGui::Text("ds: %lX", (u64)Regs.ds);
    ImGui::NextColumn();
    ImGui::Text("es: %lX", (u64)Regs.es);
    ImGui::NextColumn();
    ImGui::Text("fs: %lX", (u64)Regs.fs);
    ImGui::NextColumn();
    ImGui::Text("gs: %lX", (u64)Regs.gs);
}

static void
ImGuiShowVariable(di_variable *Var, size_t FBReg)
{
    if(Var->LocationAtom == DW_OP_fbreg)
    {
        // TODO(mateusz): Right now only ints
        size_t VarAddress = FBReg + Var->Offset;
        
        size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
        
        type_flags TFlag = 0;
        di_base_type *Type = FindBaseTypeByOffset(Var->TypeOffset, &TFlag);
        char FormatStr[64] = {};
        StringConcat(FormatStr, "%s: ");
        StringConcat(FormatStr, BaseTypeToFormatStr(Type, TFlag));
        
        float *FloatPtr = (float *)&MachineWord;
        double *DoublePtr = (double *)&MachineWord;
        
        if(BaseTypeIsFloat(Type))
        {
            ImGui::Text(FormatStr, Var->Name, *FloatPtr);
        }
        else if(BaseTypeIsDoubleFloat(Type))
        {
            ImGui::Text(FormatStr, Var->Name, *DoublePtr);
        }
        else
        {
            ImGui::Text(FormatStr, Var->Name, MachineWord);
        }
    }
}

static size_t
PeekDebugeeMemory(size_t Address, i32 DebugeePID)
{
    size_t MachineWord = 0;
    
    MachineWord = ptrace(PTRACE_PEEKDATA, DebugeePID, Address, 0x0);
    
    return MachineWord;
    
}

static inst_type
GetInstructionType(cs_insn *Instruction)
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
                case X86_GRP_BRANCH_RELATIVE:
                {
                    Result |= INST_TYPE_RELATIVE_BRANCH;
                }break;
            }
        }
    }
    
    return Result;
}

static void
DisassembleAroundAddress(size_t Address, i32 DebugeePID)
{
    DisasmInstCount = 0;
    
    cs_insn *Instruction = {};
    size_t InstructionAddress = Address;
    for(int I = 0; I < MAX_DISASM_INSTRUCTIONS; I++)
    {
        size_t MachineWord = PeekDebugeeMemory(InstructionAddress, DebugeePID);
        
        breakpoint *BP = BreakpointFind(InstructionAddress, DebugeePID);
        if(BP)
        {
            MachineWord = (MachineWord & ~0xff) | BP->SavedOpCode;
        }
        
        int Count = cs_disasm(DisAsmHandle, (const u8 *)&MachineWord, sizeof(MachineWord),
                              InstructionAddress, 1, &Instruction);
        
        if(Count == 0) { break; }
        
        DisasmInst[I].Address = InstructionAddress;
        InstructionAddress += Instruction->size;
        
        assert(strlen(Instruction->mnemonic) < sizeof(DisasmInst[I].Mnemonic));
        assert(strlen(Instruction->op_str) < sizeof(DisasmInst[I].Operation));
        strcpy(DisasmInst[I].Mnemonic, Instruction->mnemonic);
        strcpy(DisasmInst[I].Operation, Instruction->op_str);
        DisasmInstCount++;
        
#if 0        
        if(Instruction->detail && Instruction->detail->groups_count > 0)
        {
            for(i32 GroupIndex = 0;
                GroupIndex < Instruction->detail->groups_count;
                GroupIndex++)
            {
                switch(Instruction->detail->groups[GroupIndex])
                {
                    case X86_GRP_INVALID:
                    {
                        printf("X86_GRP_INVALID, ");
                    }break;
                    case X86_GRP_JUMP:
                    {
                        printf("X86_GRP_JUMP, ");
                    }break;
                    case X86_GRP_CALL:
                    {
                        printf("X86_GRP_CALL, ");
                    }break;
                    case X86_GRP_RET:
                    {
                        printf("X86_GRP_RET, ");
                    }break;
                    case X86_GRP_INT:
                    {
                        printf("X86_GRP_INT, ");
                    }break;
                    case X86_GRP_IRET:
                    {
                        printf("X86_GRP_IRET, ");
                    }break;
                    case X86_GRP_PRIVILEGE:
                    {
                        printf("X86_GRP_PRIVILEGE, ");
                    }break;
                    case X86_GRP_BRANCH_RELATIVE:
                    {
                        printf("X86_GRP_BRANCH_RELATIVE, ");
                    }break;
                }
            }
            printf("%s: %s\n", DisasmInst[I].Mnemonic, DisasmInst[I].Operation);
        }
#endif
        
        cs_free(Instruction, 1);
    }
}

static char *
DumpFile(char *Path)
{
    FILE *FHandle = fopen(Path, "r");
    assert(FHandle);
    fseek(FHandle, 0, SEEK_END);
    u32 FileSize = ftell(FHandle);
    fseek(FHandle, 0, SEEK_SET);
    
    char *Result = (char *)malloc(FileSize + 1);
    fread(Result, FileSize, 1, FHandle);
    Result[FileSize] = '\0';
    
    return Result;
}

static void
UpdateInfo()
{
    Regs = PeekRegisters(Debuger.DebugeePID);
    DisassembleAroundAddress(Regs.rip, Debuger.DebugeePID);
}

static void
DebugeeStart()
{
#if 0    
    char *ProgramArgs[16] = {};
    ProgramArgs[0] = Debuger.DebugeeProgramPath;
    ProgramArgs[1] = Debuger.ProgramArgs;
    
    char *CurrentChar = Debuger.ProgramArgs;
    for(u32 I = 2; CurrentChar[0];)
    {
        if(CurrentChar[0] == ' ')
        {
            CurrentChar[0] = '\0';
            CurrentChar++;
            ProgramArgs[I++] = CurrentChar;
        }
        
        CurrentChar++;
    }
    
    char **WP = ProgramArgs;
    while(*WP)
    {
        printf("%s\n", *WP);
        WP++;
    }
    
    assert(false);
#endif
    i32 ProcessID = fork();
    
    // Child process
    if(ProcessID == 0)
    {
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, 0x0, 0x0);
        
        char *ProgramArgs[16] = {};
        ProgramArgs[0] = Debuger.DebugeeProgramPath;
        ProgramArgs[1] = Debuger.ProgramArgs;
        
        char *CurrentChar = Debuger.ProgramArgs;
        for(u32 I = 2; CurrentChar[0];)
        {
            if(CurrentChar[0] == ' ')
            {
                CurrentChar[0] = '\0';
                CurrentChar++;
                ProgramArgs[I++] = CurrentChar;
            }
            
            CurrentChar++;
        }
        
        execv(Debuger.DebugeeProgramPath, ProgramArgs);
    }
    else
    {
        Debuger.DebugeePID = ProcessID;
        Debuger.Flags |= DEBUGEE_FLAG_RUNNING;
        WaitForSignal(Debuger.DebugeePID);
    }
}

static void
DeallocDebugInfo()
{
    Dwarf_Error Error;
    if(Debug)
    {
        DWARF_CALL(dwarf_finish(Debug, &Error));
    }
    Debug = 0;
    
    memset(Breakpoints, 0, sizeof(breakpoint) * BreakpointCount);
    memset(DISourceFiles, 0, sizeof(di_src_file) * DISourceFilesCount);
    memset(DISourceLines, 0, sizeof(di_src_line) * DISourceLinesCount);
    memset(DIFunctions, 0, sizeof(di_function) * DIFuctionsCount);
    memset(DICompileUnits, 0, sizeof(di_compile_unit) * DICompileUnitsCount);
    
    BreakpointCount = 0;
    DisasmInstCount = 0;
    Regs = {};
    DISourceFilesCount = 0;
    DISourceLinesCount = 0;
    DIFuctionsCount = 0;
    DICompileUnitsCount = 0;
    DIBaseTypesCount = 0;
    DITypedefsCount = 0;
    DIPointerTypesCount = 0;
    DIFrameInfo = {};
    ArenaDestroy(DIArena);
    DIArena = 0x0;
}

static void
DebugStart()
{
    Breakpoints = (breakpoint *)calloc(MAX_BREAKPOINT_COUNT, sizeof(breakpoint));
    DISourceFiles = (di_src_file *)calloc(MAX_DI_SOURCE_FILES, sizeof(di_src_file));
    DISourceLines = (di_src_line *)calloc(MAX_DI_SOURCE_LINES, sizeof(di_src_line));
    DIFunctions = (di_function *)calloc(MAX_DI_FUNCTIONS, sizeof(di_function));
    DICompileUnits = (di_compile_unit *)calloc(MAX_DI_COMPILE_UNITS, sizeof(di_compile_unit));
    
    glfwInit();
    GLFWwindow *Window = glfwCreateWindow(800, 600, "debag", NULL, NULL);
    glfwMakeContextCurrent(Window);
    glewInit();
    
    glfwSetKeyCallback(Window, KeyboardButtonCallback);
    glfwSetMouseButtonCallback(Window, MouseButtonCallback);
    glfwSetCursorPosCallback(Window, MousePositionCallback);
    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& IO = ImGui::GetIO(); (void)IO;
    ImGui::StyleColorsDark();
    
    ImGui_ImplGlfw_InitForOpenGL(Window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    
    glClearColor(0.5f, 0.5f, 0.5f, 1.0f);
    
    char TextBuff[64] = {};
    char TextBuff2[64] = {};
    char TextBuff3[64] = {};
    strcpy(TextBuff3, Debuger.DebugeeProgramPath);
    
#if 0    
    if(Debuger.DebugeeProgramPath)
    {
        DebugeeStart();
    }
#endif
    
    Regs = PeekRegisters(Debuger.DebugeePID);
    
    ImGuiInputTextFlags ITFlags = 0;
    ITFlags |= ImGuiInputTextFlags_EnterReturnsTrue;
    
    assert(cs_open(CS_ARCH_X86, CS_MODE_64, &DisAsmHandle) == CS_ERR_OK);
    //cs_option(DisAsmHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); 
    cs_option(DisAsmHandle, CS_OPT_DETAIL, CS_OPT_ON); 
    
#if 0    
    DWARFReadDebug();
    // NOTE(mateusz): For debug purpouses
    size_t EntryPointAddress = FindEntryPointAddress();
    assert(EntryPointAddress);
    
    breakpoint BP = BreakpointCreate(EntryPointAddress, Debuger.DebugeePID);
    BreakpointEnable(&BP);
    Breakpoints[BreakpointCount++] = BP;
#endif
    
    //size_t Addr = GetDebugeeLoadAddress(Debuger.DebugeePID);
    
    while(!glfwWindowShouldClose(Window))
    {
        //if(!Debuger.InputChange) { goto EndDraw; }
        //else { Debuger.InputChange = false; }
        
        glClear(GL_COLOR_BUFFER_BIT);
        
        if(KeyboardButtons[GLFW_KEY_F5].Pressed)
        {
            //Continue or start program
            if(!(Debuger.Flags & DEBUGEE_FLAG_RUNNING))
            {
                DebugeeStart();
                DWARFRead();
                
                // NOTE(mateusz): For debug purpouses
                size_t EntryPointAddress = FindEntryPointAddress();
                assert(EntryPointAddress);
                
                breakpoint BP = BreakpointCreate(EntryPointAddress, Debuger.DebugeePID);
                BreakpointEnable(&BP);
                Breakpoints[BreakpointCount++] = BP;
            }
            
            ContinueProgram(Debuger.DebugeePID);
            UpdateInfo();
        }
        
        if(KeyboardButtons[GLFW_KEY_F10].Pressed)
        {
            ToNextLine(Debuger.DebugeePID, false);
            UpdateInfo();
        }
        
        if(KeyboardButtons[GLFW_KEY_F11].Pressed)
        {
            ToNextLine(Debuger.DebugeePID, true);
            UpdateInfo();
        }
        
        ImGuiStartFrame();
        
        ImGui::Begin("Control window");
        
        for(u32 I = 0; I < DisasmInstCount; I++)
        {
            disasm_inst *Inst = &DisasmInst[I];
            
            if(Inst->Address == Regs.rip)
            {
                ImGui::TextColored(CurrentLineColor,
                                   "0x%" PRIx64 ":\t%s\t\t%s\n",
                                   Inst->Address, Inst->Mnemonic, Inst->Operation);
            }
            else
            {
                ImGui::Text("0x%" PRIx64 ":\t%s\t\t%s\n",
                            Inst->Address, Inst->Mnemonic, Inst->Operation);
            }
        }
        
        ImGui::End();
        
        ImGui::Begin("Program variables");
        
        ImGuiTabBarFlags TBFlags = ImGuiTabBarFlags_Reorderable;
        TBFlags |= ImGuiTabBarFlags_FittingPolicyResizeDown;
        TBFlags |= ImGuiTabBarFlags_FittingPolicyScroll;
        
        if(ImGui::BeginTabBar("Vars", TBFlags))
        {
            if(ImGui::BeginTabItem("Locals"))
            {
                di_function *Func = FindFunctionConfiningAddress(Regs.rip);
                if(Func && Func->FrameBaseIsCFA)
                {
                    size_t FBReg = DWARFGetCFA(Regs.rip);
                    for(u32 I = 0; I < Func->DIParamsCount; I++)
                    {
                        di_variable *Param = &Func->DIParams[I];
                        ImGuiShowVariable(Param, FBReg);
                    }
                    
                    for(u32 I = 0; I < Func->DIFuncLexScope.DIVariablesCount; I++)
                    {
                        di_variable *Var = &Func->DIFuncLexScope.DIVariables[I];
                        ImGuiShowVariable(Var, FBReg);
                    }
                    
                    for(u32 LexScopeIndex = 0;
                        LexScopeIndex < Func->DILexScopeCount;
                        LexScopeIndex++)
                    {
                        di_lexical_scope *LexScope = &Func->DILexScopes[LexScopeIndex];
                        
                        if(LexScope->RangesCount == 0)
                        {
                            if(AddressBetween(Regs.rip, LexScope->LowPC, LexScope->HighPC - 1))
                            {
                                for(u32 I = 0; I < LexScope->DIVariablesCount; I++)
                                {
                                    di_variable *Var = &LexScope->DIVariables[I];
                                    ImGuiShowVariable(Var, FBReg);
                                }
                            }
                        }
                        else
                        {
                            for(u32 RIndex = 0; RIndex < LexScope->RangesCount; RIndex++)
                            {
                                if(AddressBetween(Regs.rip, LexScope->RangesLowPCs[RIndex], LexScope->RangesHighPCs[RIndex] - 1))
                                {
                                    for(u32 I = 0; I < LexScope->DIVariablesCount; I++)
                                    {
                                        di_variable *Var = &LexScope->DIVariables[I];
                                        ImGuiShowVariable(Var, FBReg);
                                    }
                                }
                            }
                        }
                    }
                }
                
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("x64 Registers"))
            {
                ImGuiShowRegisters(Regs);
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Control panel"))
            {
                ImGui::InputText("Program path", TextBuff3, 64, ITFlags);
                ImGui::InputText("Program args", Debuger.ProgramArgs, 64, ITFlags);
                
                ImGui::InputText("", TextBuff, 64, ITFlags);
                ImGui::SameLine();
                
                if(ImGui::Button("Break"))
                {
                    u64 Address;
                    
                    if(CharInString(TextBuff, 'x'))
                    {
                        Address = HexStringToInt(TextBuff);
                    }
                    else
                    {
                        Address = atol(TextBuff);
                    }
                    
                    breakpoint BP = BreakpointCreate(Address, Debuger.DebugeePID);
                    BreakpointEnable(&BP);
                    Breakpoints[BreakpointCount++] = BP;
                    
                    UpdateInfo();
                }
                
                ImGui::InputText("tbr", TextBuff2, 64, ITFlags);
                ImGui::SameLine();
                
                if(ImGui::Button("BreakFunc"))
                {
                    for(u32 I = 0; I < DIFuctionsCount; I++)
                    {
                        di_function *Func = &DIFunctions[I];
                        if(strcmp(TextBuff2, Func->Name) == 0)
                        {
                            breakpoint BP = BreakpointCreate(Func->DIFuncLexScope.LowPC, Debuger.DebugeePID);
                            BreakpointEnable(&BP);
                            Breakpoints[BreakpointCount++] = BP;
                        }
                    }
                    
                    UpdateInfo();
                }
                
                if(ImGui::Button("Continue") || KeyboardButtons[GLFW_KEY_F5].Pressed)
                {
                    ContinueProgram(Debuger.DebugeePID);
                    UpdateInfo();
                }
                
                if(ImGui::Button("Single Step"))
                {
                    StepInstruction(Debuger.DebugeePID);
                    UpdateInfo();
                }
                
                if(ImGui::Button("Next") || KeyboardButtons[GLFW_KEY_F10].Pressed)
                {
                    ToNextLine(Debuger.DebugeePID, false);
                    UpdateInfo();
                }
                
                ImGui::SameLine();
                
                if(ImGui::Button("Step") || KeyboardButtons[GLFW_KEY_F11].Pressed)
                {
                    ToNextLine(Debuger.DebugeePID, true);
                    UpdateInfo();
                }
                
                if(!(Debuger.Flags & DEBUGEE_FLAG_RUNNING) && ImGui::Button("Restart process"))
                {
                    DebugeeStart();
                    
                    // NOTE(mateusz): For debug purpouses
                    size_t EntryPointAddress = FindEntryPointAddress();
                    assert(EntryPointAddress);
                    
                    breakpoint BP = BreakpointCreate(EntryPointAddress, Debuger.DebugeePID);
                    BreakpointEnable(&BP);
                    Breakpoints[BreakpointCount++] = BP;
                    
                    DWARFRead();
                }
                
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        
        
        ImGui::End();
        
        ImGui::Begin("Listings");
        
        TBFlags = ImGuiTabBarFlags_Reorderable;
        TBFlags |= ImGuiTabBarFlags_FittingPolicyResizeDown;
        TBFlags |= ImGuiTabBarFlags_FittingPolicyScroll;
        
        if(ImGui::BeginTabBar("Source and Disassebmly", TBFlags))
        {
            if(ImGui::BeginTabItem("Source code"))
            {
                di_src_line *Line = LineTableFindByAddress(Regs.rip);
                
                if(Line)
                {
                    di_src_file *Src = &DISourceFiles[Line->SrcFileIndex];
                    
                    char *LinePtr = Src->Content;
                    char *Prev = 0x0;
                    for(u32 I = 0; I < Src->LineCount + 1; I++)
                    {
                        Prev = LinePtr;
                        LinePtr = strchr(LinePtr, '\n') + 1;
                        u32 LineLength = (u64)LinePtr - (u64)Prev;
                        
                        // NOTE(mateusz): Lines are indexed from 1
                        if(Line->LineNum == I + 1)
                        {
                            ImGui::TextColored(CurrentLineColor, "%.*s",
                                               LineLength, Prev);
                            ImGui::SetScrollHereY(0.5f);
                        }
                        else
                        {
                            di_src_line *DrawingLine = LineTableFindByLineNum(I + 1);
                            
                            if(DrawingLine && BreakpointFind(DrawingLine->Address, Debuger.DebugeePID))
                            {
                                ImGui::TextColored(BreakpointLineColor, "%.*s",
                                                   LineLength, Prev);
                            }
                            else
                            {
                                ImGui::Text("%.*s", LineLength, Prev);
                            }
                        }
                    }
                }
                
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("Disassembly"))
            {
                
                ImGui::EndTabItem();
            }
            
            ImGui::EndTabBar();
        }
        
        ImGui::End();
        
        ImGuiEndFrame();
        //EndDraw:;
        ButtonsUpdate(KeyboardButtons, (sizeof(KeyboardButtons)/sizeof(KeyboardButtons[0])));
        glfwPollEvents();
        glfwSwapBuffers(Window);
    }
}

int
main(i32 ArgCount, char **Args)
{
    if(ArgCount != 2)
    {
        return -1;
    }
    
    Debuger.DebugeeProgramPath = Args[1];
    DebugStart();
    
    return 0;
}
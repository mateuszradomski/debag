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

#include <GL/glew.h>
#include <GLFW/glfw3.h>
#include <capstone/capstone.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

#include <libs/imgui/imgui.h>
#include <libs/imgui/imgui_impl_glfw.h>
#include <libs/imgui/imgui_impl_opengl3.h>

#include "debag.h"
#include "utils.h"
#include "dwarf.h"
#include "utils.cpp"
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
    
    WindowWidth = Width;
    WindowHeight = Height;
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
StringsMatch(char *Str0, char *Str1)
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
ImGuiShowValueAsString(size_t DereferencedAddress)
{
    char Temp[256] = {};
    u32 TIndex = 0;
    
    Temp[TIndex++] = '\"';
    if(DereferencedAddress)
    {
        size_t MachineWord = PeekDebugeeMemory(DereferencedAddress, Debuger.DebugeePID);
        char *PChar = (char *)&MachineWord;
        
        int RemainingBytes = sizeof(MachineWord);
        while(PChar[0] && IS_PRINTABLE(PChar[0]))
        {
            Temp[TIndex++] = PChar[0];
            PChar += 1;
            
            RemainingBytes -= 1;
            if(RemainingBytes == 0)
            {
                RemainingBytes = sizeof(MachineWord);
                DereferencedAddress += sizeof(MachineWord);
                
                MachineWord = PeekDebugeeMemory(DereferencedAddress, Debuger.DebugeePID);
                PChar = (char *)&MachineWord;
            }
        }
    }
    Temp[TIndex++] = '\"';
    assert(TIndex < sizeof(Temp));
    
    char AddrTemp[24] = {};
    sprintf(AddrTemp, " (%p)", (void *)DereferencedAddress);
    
    for(u32 I = 0; I < sizeof(AddrTemp); I++)
    {
        Temp[TIndex++] = AddrTemp[I];
    }
    assert(TIndex < sizeof(Temp));
    
    ImGui::Text("%s", Temp);
}

static void
ImGuiShowBaseType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    di_base_type *BType = Underlaying.Type;
    size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
    
    ImGui::Text("%s", VarName);
    ImGui::NextColumn();
    
    union types_ptrs
    {
        void *Void;
        float *Float;
        double *Double;
        char *Char;
        short *Short;
        int *Int;
        long long *Long;
    } TypesPtrs;
    TypesPtrs.Void = &MachineWord;
    
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        if(BType->Encoding == DW_ATE_signed_char && Underlaying.PointerCount == 1)
        {
            size_t DereferencedAddress = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
            ImGuiShowValueAsString(DereferencedAddress);
        }
        else
        {
            ImGui::Text("%p", TypesPtrs.Void);
        }
    }
    else
    {
        switch(BType->ByteSize)
        {
            case 1:
            {
                if(BType->Encoding == DW_ATE_signed_char)
                {
                    ImGui::Text("%c (%x)", *TypesPtrs.Char, (*TypesPtrs.Char));
                }
                else
                {
                    ImGui::Text("%u", (unsigned int)*TypesPtrs.Char);
                }
            }break;
            case 2:
            {
                if(BType->Encoding == DW_ATE_signed)
                {
                    ImGui::Text("%d", *TypesPtrs.Short);
                }
                else
                {
                    ImGui::Text("%u", (unsigned int)*TypesPtrs.Short);
                }
            }break;
            case 4:
            {
                if(BType->Encoding == DW_ATE_unsigned)
                {
                    ImGui::Text("%u", (unsigned int)*TypesPtrs.Int);
                }
                else if(BType->Encoding == DW_ATE_float)
                {
                    ImGui::Text("%f", *TypesPtrs.Float);
                }
                else
                {
                    ImGui::Text("%d", *TypesPtrs.Int);
                }
            }break;
            case 8:
            {
                if(BType->Encoding == DW_ATE_unsigned)
                {
                    ImGui::Text("%llu", (unsigned long long)*TypesPtrs.Long);
                }
                else if(BType->Encoding == DW_ATE_float)
                {
                    ImGui::Text("%f", *TypesPtrs.Double);
                }
                else
                {
                    ImGui::Text("%lld", *TypesPtrs.Long);
                }
            }break;
            default:
            {
                printf("Unsupported byte size = %d", BType->ByteSize);
            }break;
        }
    }
    
    char TypeName[128] = {};
    strcat(TypeName, Underlaying.Name);
    
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        strcat(TypeName, " *");
    }
    
    ImGui::NextColumn();
    ImGui::Text("%s", TypeName);
    ImGui::NextColumn();
}

static void
ImGuiShowStructType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    di_struct_type *Struct = Underlaying.Struct;
    size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
    
    char TypeName[128] = {};
    StringConcat(TypeName, Underlaying.Name);
    
    // TODO(mateusz): Stacked pointers dereference, like (void **)
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        VarAddress = MachineWord;
        
        strcat(TypeName, " *");
    }
    
    bool Open = ImGui::TreeNode(VarName, "%s", VarName);
    ImGui::NextColumn();
    ImGui::Text("0x%lx", VarAddress);
    ImGui::NextColumn();
    ImGui::Text("%s", TypeName);
    ImGui::NextColumn();
    
    if(Open)
    {
        for(u32 MemberIndex = 0; MemberIndex < Struct->MembersCount; MemberIndex++)
        {
            di_struct_member *Member = &Struct->Members[MemberIndex];
            size_t MemberAddress = VarAddress + Member->ByteLocation;
            assert(Member->Name);
            
            ImGuiShowVariable(Member->ActualTypeOffset, MemberAddress, Member->Name);
        }
        
        ImGui::TreePop();
    }
    
}

static void
ImGuiShowArrayType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    char TypeName[128] = {};
    strcat(TypeName, Underlaying.Name);
    size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
    
    // TODO(mateusz): Stacked pointers dereference, like (void **)
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        VarAddress = MachineWord;
        
        strcat(TypeName, " *");
    }
    
    bool Open = ImGui::TreeNode(VarName, "%s", VarName);
    ImGui::NextColumn();
    if(Underlaying.Type->Encoding == DW_ATE_signed_char)
    {
        ImGuiShowValueAsString(VarAddress);
    }
    else
    {
        ImGui::Text("0x%lx", VarAddress);
    }
    
    ImGui::NextColumn();
    ImGui::Text("%s[%ld]", TypeName, Underlaying.ArrayUpperBound + 1);
    ImGui::NextColumn();
    
    if(Open)
    {
        for(u32 I = 0; I <= Underlaying.ArrayUpperBound; I++)
        {
            //size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
            
            if(Underlaying.Flags & TYPE_IS_STRUCT || Underlaying.Flags & TYPE_IS_UNION)
            {
                char VarNameWI[128] = {};
                sprintf(VarNameWI, "%s[%d]", VarName, I);
                
                ImGuiShowStructType(Underlaying, VarAddress, VarNameWI);
                
                VarAddress += Underlaying.Struct->ByteSize;
            }
            else if(Underlaying.Flags & TYPE_IS_BASE)
            {
                char VarNameWI[128] = {};
                sprintf(VarNameWI, "%s[%d]", VarName, I);
                
                ImGuiShowBaseType(Underlaying, VarAddress, VarNameWI);
                
                VarAddress += Underlaying.Type->ByteSize;
            }
            else
            {
                //printf("Var [%s] doesn't have a type\n", VarName);
                //assert(false);
            }
        }
        ImGui::TreePop();
    }
}

static void
ImGuiShowVariable(size_t TypeOffset, size_t VarAddress, char *VarName = "")
{
    di_underlaying_type Underlaying = FindUnderlayingType(TypeOffset);
    
    if(Underlaying.Flags & TYPE_IS_ARRAY)
    {
        ImGuiShowArrayType(Underlaying, VarAddress, VarName);
    }
    else if(Underlaying.Flags & TYPE_IS_STRUCT || Underlaying.Flags & TYPE_IS_UNION)
    {
        // NOTE(mateusz): We are treating unions and struct as the same thing, but with ByteLocation = 0
        assert(sizeof(di_union_type) == sizeof(di_struct_type));
        assert(sizeof(di_union_member) == sizeof(di_struct_member));
        
        ImGuiShowStructType(Underlaying, VarAddress, VarName);
    }
    else if(Underlaying.Flags & TYPE_IS_BASE)
    {
        ImGuiShowBaseType(Underlaying, VarAddress, VarName);
    }
    else
    {
        //printf("Var [%s] doesn't have a type\n", VarName);
        //assert(false);
    }
}

static void
ImGuiShowVariable(di_variable *Var, size_t FBReg)
{
    // TODO(mateusz): Other ways of accessing variables
    if(Var->LocationAtom == DW_OP_fbreg)
    {
        size_t VarAddress = FBReg + Var->Offset;
        ImGuiShowVariable(Var->TypeOffset, VarAddress, Var->Name);
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
DisassembleAroundAddress(address_range AddrRange, i32 DebugeePID)
{
    DisasmInstCount = 0;
    
    cs_insn *Instruction = {};
    size_t InstructionAddress = AddrRange.Start;
    for(int I = 0; I < MAX_DISASM_INSTRUCTIONS && InstructionAddress < AddrRange.End; I++)
    {
        u8 InstrInMemory[16] = {};
        size_t *MemoryPtr = (size_t *)InstrInMemory;
        
        size_t TempAddress = InstructionAddress;
        for(u32 I = 0; I < sizeof(InstrInMemory) / sizeof(size_t); I++)
        {
            *MemoryPtr = PeekDebugeeMemory(TempAddress, DebugeePID);
            MemoryPtr += 1;
            TempAddress += 1;
            if(TempAddress >= AddrRange.End)
            {
                break;
            }
        }
        
        breakpoint *BP = 0x0; ;
        if((BP = BreakpointFind(InstructionAddress, DebugeePID)) && BreakpointEnabled(BP))
        {
            InstrInMemory[0] = BP->SavedOpCode;
        }
        
        int Count = cs_disasm(DisAsmHandle, InstrInMemory, sizeof(InstrInMemory),
                              InstructionAddress, 1, &Instruction);
        
        // TODO(mateusz): In the tests_bin/variables program there are weird bytes
        // between instructions, looks kinda like padding. I guess to get around it
        // I have to disassemble between CU LowPC and HighPC.
        // NOTE(mateusz): Comments are always out of date, i feel like it's already solved
        // 2020.12.16
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
    
    di_function *Func = FindFunctionConfiningAddress(Regs.rip);
    if(Func)
    {
        assert(Func->FuncLexScope.RangesCount == 0);
        address_range LexScopeRange = {};
        LexScopeRange.Start = Func->FuncLexScope.LowPC;
        LexScopeRange.End = Func->FuncLexScope.HighPC;
        
        DisassembleAroundAddress(LexScopeRange, Debuger.DebugeePID);
    }
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
        prctl(PR_SET_PDEATHSIG, SIGHUP);
        
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
    if(DI->Debug)
    {
        DWARF_CALL(dwarf_finish(DI->Debug, &Error));
    }
    DI->Debug = 0;
    
    memset(Breakpoints, 0, sizeof(breakpoint) * BreakpointCount);
    memset(DI->SourceFiles, 0, sizeof(di_src_file) * DI->SourceFilesCount);
//    memset(DI->SourceLines, 0, sizeof(di_src_line) * DI->SourceLinesCount);
    memset(DI->Functions, 0, sizeof(di_function) * DI->FuctionsCount);
    memset(DI->CompileUnits, 0, sizeof(di_compile_unit) * DI->CompileUnitsCount);
    memset(DI->Variables, 0, sizeof(di_variable) * DI->VariablesCount);
    memset(DI->Params, 0, sizeof(di_variable) * DI->ParamsCount);
    memset(DI->BaseTypes, 0, sizeof(di_base_type) * DI->BaseTypesCount);
    memset(DI->Typedefs, 0, sizeof(di_typedef) * DI->TypedefsCount);
    memset(DI->PointerTypes, 0, sizeof(di_pointer_type) * DI->PointerTypesCount);
    memset(DI->StructMembers, 0, sizeof(di_struct_member) * DI->StructMembersCount);
    memset(DI->StructTypes, 0, sizeof(di_struct_type) * DI->StructTypesCount);
    memset(DI->ArrayTypes, 0, sizeof(di_array_type) * DI->ArrayTypesCount);
    memset(DI->LexScopes, 0, sizeof(di_lexical_scope) * DI->LexScopesCount);
    
    BreakpointCount = 0;
    DisasmInstCount = 0;
    Regs = {};
    DI->SourceFilesCount = 0;
//    DI->SourceLinesCount = 0;
    DI->VariablesCount = 0;
    DI->ParamsCount = 0;
    DI->FuctionsCount = 0;
    DI->CompileUnitsCount = 0;
    DI->BaseTypesCount = 0;
    DI->TypedefsCount = 0;
    DI->PointerTypesCount = 0;
    DI->StructMembersCount = 0;
    DI->StructTypesCount = 0;
    DI->ArrayTypesCount = 0;
    DI->LexScopesCount = 0;
    DI->FrameInfo = {};
    ArenaDestroy(DI->Arena);
    DI->Arena = 0x0;
}

static void
DebugerMain()
{
    Breakpoints = (breakpoint *)calloc(MAX_BREAKPOINT_COUNT, sizeof(breakpoint));
    DI = (debug_info *)calloc(1, sizeof(debug_info));
    DI->SourceFiles = (di_src_file *)calloc(MAX_DI_SOURCE_FILES, sizeof(di_src_file));
//    DI->SourceLines = (di_src_line *)calloc(MAX_DI_SOURCE_LINES, sizeof(di_src_line));
    
    glfwInit();
    GLFWwindow *Window = glfwCreateWindow(WindowWidth, WindowHeight, "debag", NULL, NULL);
    glfwMakeContextCurrent(Window);
    glewInit();
    
    glfwSetKeyCallback(Window, KeyboardButtonCallback);
    glfwSetMouseButtonCallback(Window, MouseButtonCallback);
    glfwSetCursorPosCallback(Window, MousePositionCallback);
    glfwSetWindowSizeCallback(Window, WindowSizeCallback);
    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& IO = ImGui::GetIO(); (void)IO;
    ImGui::StyleColorsDark();
    
    ImGui_ImplGlfw_InitForOpenGL(Window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    
    // Make windows square not round
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    
    glClearColor(0.5f, 0.5f, 0.5f, 1.0f);
    
    char TextBuff[64] = {};
    char TextBuff2[64] = {};
    char TextBuff3[64] = {};
    strcpy(TextBuff3, Debuger.DebugeeProgramPath);
    
    Regs = PeekRegisters(Debuger.DebugeePID);
    
    ImGuiInputTextFlags ITFlags = 0;
    ITFlags |= ImGuiInputTextFlags_EnterReturnsTrue;
    
    ImGuiTabBarFlags TBFlags = ImGuiTabBarFlags_Reorderable;
    TBFlags |= ImGuiTabBarFlags_FittingPolicyResizeDown;
    TBFlags |= ImGuiTabBarFlags_FittingPolicyScroll;
    
    ImGuiWindowFlags WinFlags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse;
    
    assert(cs_open(CS_ARCH_X86, CS_MODE_64, &DisAsmHandle) == CS_ERR_OK);
    //cs_option(DisAsmHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); 
    cs_option(DisAsmHandle, CS_OPT_DETAIL, CS_OPT_ON); 
    
    //size_t Addr = GetDebugeeLoadAddress(Debuger.DebugeePID);
    
    while(!glfwWindowShouldClose(Window))
    {
        //if(!Debuger.InputChange) { goto EndDraw; }
        //else { Debuger.InputChange = false; }
        
        // NOTE(mateusz): This has to happen before the calls to next lines
        if(Debuger.Flags & DEBUGEE_FLAG_STEPED)
        {
            Debuger.Flags ^= DEBUGEE_FLAG_STEPED;
        }
        
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
                printf("%lx\n", EntryPointAddress);
                assert(EntryPointAddress);
                
                breakpoint BP = BreakpointCreate(EntryPointAddress, Debuger.DebugeePID);
                BreakpointEnable(&BP);
                Breakpoints[BreakpointCount++] = BP;
            }
            
            ContinueProgram(Debuger.DebugeePID);
            UpdateInfo();
        }
        
        if(KeyboardButtons[GLFW_KEY_F10].Pressed || KeyboardButtons[GLFW_KEY_F10].Repeat)
        {
            ToNextLine(Debuger.DebugeePID, false);
            UpdateInfo();
        }
        
        if(KeyboardButtons[GLFW_KEY_F11].Pressed || KeyboardButtons[GLFW_KEY_F11].Repeat)
        {
            ToNextLine(Debuger.DebugeePID, true);
            UpdateInfo();
        }
        
        ImGuiStartFrame();
        
        ImGui::Begin("Disassembly", 0x0, WinFlags);
        
        ImGui::SetWindowPos(ImVec2(WindowWidth / 2, 0));
        ImGui::SetWindowSize(ImVec2(WindowWidth / 2, (WindowHeight / 3) * 2));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
        
        for(u32 I = 0; I < DisasmInstCount; I++)
        {
            disasm_inst *Inst = &DisasmInst[I];
            
            if(Inst->Address == Regs.rip)
            {
                ImGui::TextColored(CurrentLineColor,
                                   "0x%" PRIx64 ":\t%s\t\t%s\n",
                                   Inst->Address, Inst->Mnemonic, Inst->Operation);
                
                if(Debuger.Flags & DEBUGEE_FLAG_STEPED)
                {
                    ImGui::SetScrollHereY(0.5f);
                }
            }
            else
            {
                ImGui::Text("0x%" PRIx64 ":\t%s\t\t%s\n",
                            Inst->Address, Inst->Mnemonic, Inst->Operation);
            }
        }
        
        ImGui::PopStyleVar();
        ImGui::End();
        
        ImGui::Begin("Listings", 0x0, WinFlags);
        ImGui::SetWindowPos(ImVec2(0, 0));
        ImGui::SetWindowSize(ImVec2(WindowWidth / 2, (WindowHeight / 3) * 2));
        
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
        
        if(ImGui::BeginTabBar("Source lines", TBFlags | ImGuiTabBarFlags_AutoSelectNewTabs))
        {
            di_src_line *Line = LineTableFindByAddress(Regs.rip);
            for(u32 SrcFileIndex = 0; SrcFileIndex < DI->SourceFilesCount; SrcFileIndex++)
            {
                ImGuiTabItemFlags TIFlags = ImGuiTabItemFlags_None;
                if(SrcFileIndex == Line->SrcFileIndex && Debuger.Flags & DEBUGEE_FLAG_STEPED)
                {
                    TIFlags = ImGuiTabItemFlags_SetSelected;
                }
                
                (void)TIFlags;
                
                char *FileName = StringFindLastChar(DI->SourceFiles[SrcFileIndex].Path, '/') + 1;
                if(ImGui::BeginTabItem(FileName, NULL, TIFlags))
                {
                    //printf("child on %u\n", SrcFileIndex);
                    ImGui::BeginChild("srcfile");
                    
                    di_src_file *Src = &DI->SourceFiles[SrcFileIndex];
                    di_src_line *DrawingLine = 0x0;
                    char *LinePtr = Src->Content;
                    char *Prev = 0x0;
                    for(u32 I = 0; I < Src->ContentLineCount + 1; I++)
                    {
                        Prev = LinePtr;
                        LinePtr = strchr(LinePtr, '\n') + 1;
                        u32 LineLength = (u64)LinePtr - (u64)Prev;
                        
                        // NOTE(mateusz): Lines are indexed from 1
                        if(SrcFileIndex == Line->SrcFileIndex && Line->LineNum == I + 1)
                        {
                            DrawingLine = Line;
                            ImGui::TextColored(CurrentLineColor, "%.*s", LineLength, Prev);
                            
                            if(Debuger.Flags & DEBUGEE_FLAG_STEPED)
                            {
                                ImGui::SetScrollHereY(0.5f);
                            }
                        }
                        else
                        {
                            di_src_line *TempLine = LineFindByNumber(I + 1, SrcFileIndex);
                            if(TempLine)
                            {
                                DrawingLine = TempLine;
                            }
                            
                            breakpoint *BP = 0x0;
                            
                            if(DrawingLine &&
                               (BP = BreakpointFind(DrawingLine->Address, Debuger.DebugeePID)) &&
                               BreakpointEnabled(BP)){
                                //printf("[%u] = DrawingLine->Address = %lx\n", SrcFileIndex, DrawingLine->Address);
                                ImGui::TextColored(BreakpointLineColor, "%.*s",
                                                   LineLength, Prev);
                            }
                            else
                            {
                                ImGui::Text("%.*s", LineLength, Prev);
                            }
                        }
                        
                        if(ImGui::IsItemClicked())
                        {
                            // TODO(mateusz): This NEEDS to be better and not settings breakpoints
                            // at comments and other garbage
                            if(DrawingLine)
                            {
                                breakpoint *BP = BreakpointFind(DrawingLine->Address, Debuger.DebugeePID);
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
                                        BreakpointPushAtSourceLine(Src, DrawingLine->LineNum, Breakpoints, &BreakpointCount);
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
        
        ImGui::Begin("Program variables", 0x0, WinFlags);
        
        ImGui::SetWindowPos(ImVec2(0, (WindowHeight / 3) * 2));
        ImGui::SetWindowSize(ImVec2(WindowWidth, WindowHeight / 3));
        
        if(ImGui::BeginTabBar("Vars", TBFlags))
        {
            if(ImGui::BeginTabItem("Locals"))
            {
                ImGui::BeginChild("regs");
                ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
                
                di_function *Func = FindFunctionConfiningAddress(Regs.rip);
                if(Func && Func->FrameBaseIsCFA)
                {
                    size_t FBReg = DWARFGetCFA(Regs.rip);
                    
                    ImGui::Columns(3, "tree", true);
                    
                    ImGui::Text("Name"); ImGui::NextColumn();
                    ImGui::Text("Value"); ImGui::NextColumn();
                    ImGui::Text("Type"); ImGui::NextColumn();
                    ImGui::Separator();
                    
                    for(u32 I = 0; I < Func->ParamCount; I++)
                    {
                        di_variable *Param = &Func->Params[I];
                        ImGuiShowVariable(Param, FBReg);
                    }
                    
                    for(u32 I = 0; I < Func->FuncLexScope.VariablesCount; I++)
                    {
                        di_variable *Var = &Func->FuncLexScope.Variables[I];
                        ImGuiShowVariable(Var, FBReg);
                    }
                    
                    for(u32 LexScopeIndex = 0;
                        LexScopeIndex < Func->LexScopesCount;
                        LexScopeIndex++)
                    {
                        di_lexical_scope *LexScope = &Func->LexScopes[LexScopeIndex];
                        
                        if(LexScope->RangesCount == 0)
                        {
                            if(AddressBetween(Regs.rip, LexScope->LowPC, LexScope->HighPC - 1))
                            {
                                for(u32 I = 0; I < LexScope->VariablesCount; I++)
                                {
                                    di_variable *Var = &LexScope->Variables[I];
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
                                    for(u32 I = 0; I < LexScope->VariablesCount; I++)
                                    {
                                        di_variable *Var = &LexScope->Variables[I];
                                        ImGuiShowVariable(Var, FBReg);
                                    }
                                }
                            }
                        }
                    }
                }
                else if(Func)
                {
                    assert(false);
                }
                
                ImGui::PopStyleVar();
                ImGui::EndChild();
                ImGui::Columns(1);
                ImGui::EndTabItem();
            }
            if(ImGui::BeginTabItem("x64 Registers"))
            {
                ImGui::BeginChild("regs");
                ImGuiShowRegisters(Regs);
                ImGui::EndChild();
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
                    for(u32 I = 0; I < DI->FuctionsCount; I++)
                    {
                        di_function *Func = &DI->Functions[I];
                        if(strcmp(TextBuff2, Func->Name) == 0)
                        {
                            breakpoint BP = BreakpointCreate(Func->FuncLexScope.LowPC, Debuger.DebugeePID);
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
            if(ImGui::BeginTabItem("Breakpoints"))
            {
                for(u32 I = 0; I < BreakpointCount; I++)
                {
                    ImGui::Text("Breakpoint at %lX\n", Breakpoints[I].Address);
                }
                
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
    DebugerMain();
    
    return 0;
}

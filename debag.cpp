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

#include <debag.h>
#include <flow.cpp>

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

static inline bool
AddressBetween(size_t Address, size_t Lower, size_t Upper)
{
    bool Result = false;
    
    Result = (Address >= Lower) && (Address <= Upper);
    
    return Result;
}

static di_src_line *
LineTableFindByAddress(size_t Address)
{
    for(i32 I = 0; I < DWLineEntriesCount; I++)
    {
        if(DWLineTable[I].Address == Address)
        {
            return &DWLineTable[I];
        }
        else if(I + 1 < DWLineEntriesCount &&
                (DWLineTable[I].Address < Address) &&
                (DWLineTable[I + 1].Address > Address))
        {
            return &DWLineTable[I];
        }
    }
    
    return 0x0;
}

static di_src_line *
LineTableFindByLineNum(u32 LineNum)
{
    for(i32 I = 0; I < DWLineEntriesCount; I++)
    {
        if(DWLineTable[I].LineNum == LineNum)
        {
            return &DWLineTable[I];
        }
    }
    
    return 0x0;
}

static address_range
LineAddressRangeBetween(di_src_line *StartLine, di_src_line *EndLine)
{
    address_range Result = {};
    
    Result.Start = StartLine->Address;
    Result.End = EndLine->Address;
    
    return Result;
}

static dwarf_function *
FindFunctionConfiningAddress(size_t Address)
{
    dwarf_function *Result = 0x0;
    
    for(u32 I = 0; I < DWFunctionsCount; I++)
    {
        if(AddressBetween(Address, DWFunctions[I].LowPC, DWFunctions[I].HighPC))
        {
            Result = &DWFunctions[I];
            break;
        }
    }
    
    return Result;
}

static void
ImGuiShowRegisters(user_regs_struct Regs)
{
    ImGui::Columns(4, 0x0, true);
    
    ImGui::Text("r15: %X", Regs.r15);
    ImGui::NextColumn();
    ImGui::Text("r14: %X", Regs.r14);
    ImGui::NextColumn();
    ImGui::Text("r13: %X", Regs.r13);
    ImGui::NextColumn();
    ImGui::Text("r12: %X", Regs.r12);
    ImGui::NextColumn();
    ImGui::Text("rbp: %X", Regs.rbp);
    ImGui::NextColumn();
    ImGui::Text("rbx: %X", Regs.rbx);
    ImGui::NextColumn();
    ImGui::Text("r11: %X", Regs.r11);
    ImGui::NextColumn();
    ImGui::Text("r10: %X", Regs.r10);
    ImGui::NextColumn();
    ImGui::Text("r9: %X", Regs.r9);
    ImGui::NextColumn();
    ImGui::Text("r8: %X", Regs.r8);
    ImGui::NextColumn();
    ImGui::Text("rax: %X", Regs.rax);
    ImGui::NextColumn();
    ImGui::Text("rcx: %X", Regs.rcx);
    ImGui::NextColumn();
    ImGui::Text("rdx: %X", Regs.rdx);
    ImGui::NextColumn();
    ImGui::Text("rsi: %X", Regs.rsi);
    ImGui::NextColumn();
    ImGui::Text("rdi: %X", Regs.rdi);
    ImGui::NextColumn();
    ImGui::Text("orig_rax: %X", Regs.orig_rax);
    ImGui::NextColumn();
    ImGui::Text("rip: %X", Regs.rip);
    ImGui::NextColumn();
    ImGui::Text("cs: %X", Regs.cs);
    ImGui::NextColumn();
    ImGui::Text("eflags: %X", Regs.eflags);
    ImGui::NextColumn();
    ImGui::Text("rsp: %X", Regs.rsp);
    ImGui::NextColumn();
    ImGui::Text("ss: %X", Regs.ss);
    ImGui::NextColumn();
    ImGui::Text("fs_base: %X", Regs.fs_base);
    ImGui::NextColumn();
    ImGui::Text("gs_base: %X", Regs.gs_base);
    ImGui::NextColumn();
    ImGui::Text("ds: %X", Regs.ds);
    ImGui::NextColumn();
    ImGui::Text("es: %X", Regs.es);
    ImGui::NextColumn();
    ImGui::Text("fs: %X", Regs.fs);
    ImGui::NextColumn();
    ImGui::Text("gs: %X", Regs.gs);
}

static size_t
PeekDebugeeMemory(size_t Address, i32 DebugeePID)
{
    size_t MachineWord = 0;
    
    MachineWord = ptrace(PTRACE_PEEKDATA, DebugeePID, Address, 0x0);
    
    return MachineWord;
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

static void
ParseForLineTable(Dwarf_Debug Debug, Dwarf_Die DIE)
{
    Dwarf_Addr LowPC = 0;
    Dwarf_Addr HighPC = 0;
    i32 Result = dwarf_lowpc(DIE, &LowPC, 0x0);
    
    if(Result == DW_DLV_OK)
    {
        Dwarf_Half Form = 0;
        Dwarf_Form_Class FormType = {};
        Result = dwarf_highpc_b(DIE, &HighPC, &Form, &FormType, 0x0);
        if(Result == DW_DLV_OK)
        {
            if (FormType == DW_FORM_CLASS_CONSTANT) {
                HighPC += LowPC;
            }
            
            Dwarf_Unsigned Version = 0;
            Dwarf_Small TableType = 0;
            Dwarf_Line_Context LineCtx = 0;
            
            Result = dwarf_srclines_b(DIE, &Version, &TableType, &LineCtx, 0x0);
            if(Result == DW_DLV_OK)
            {
                Dwarf_Line *LineBuffer = 0;
                Dwarf_Signed LineCount = 0;
                
                Result = dwarf_srclines_from_linecontext(LineCtx, &LineBuffer, &LineCount, 0x0);
                assert(Result == DW_DLV_OK);
                
                for (i32 I = 0; I < LineCount; ++I) {
                    Dwarf_Addr LineAddr = 0;
                    Dwarf_Unsigned FileNum = 0;
                    Dwarf_Unsigned LineNum = 0;
                    char *LineSrcFile = 0;
                    
                    Result = dwarf_lineno(LineBuffer[I], &LineNum, 0x0);
                    assert(Result != DW_DLV_ERROR);
                    Result = dwarf_line_srcfileno(LineBuffer[I], &FileNum, 0x0);
                    assert(Result != DW_DLV_ERROR);
                    if (FileNum) {
                        FileNum -= 1;
                    }
                    Result = dwarf_lineaddr(LineBuffer[I], &LineAddr, 0x0);
                    assert(Result != DW_DLV_ERROR);
                    Result = dwarf_linesrc(LineBuffer[I], &LineSrcFile, 0x0);
                    
                    di_src_line *LTEntry = &DWLineTable[DWLineEntriesCount++];
                    LTEntry->Address = LineAddr;
                    LTEntry->LineNum = LineNum;
                    // TODO(mateusz): THAT'S BAD!
                    LTEntry->Path = strdup(LineSrcFile);
                }
            }
        }
    }
}

static void
RecurForEachDIE(Dwarf_Debug Debug, Dwarf_Die DIE, i32 RecurLevel = 0)
{
    Dwarf_Die CurrentDIE = DIE;
	Dwarf_Die SiblingDIE = DIE;
	Dwarf_Die ChildDIE = 0;
	Dwarf_Error Error = {};
    
    ParseForLineTable(Debug, DIE);
    
    /* First son, if any */
    i32 Result = dwarf_child(CurrentDIE, &ChildDIE, &Error);
    
    /* traverse tree depth first */
    if(Result == DW_DLV_OK)
    { 
        RecurForEachDIE(Debug, ChildDIE, RecurLevel + 1); /* recur on the first son */
        SiblingDIE = ChildDIE;
        while(Result == DW_DLV_OK)
        {
            CurrentDIE = SiblingDIE;
            Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, &Error);
            RecurForEachDIE(Debug, SiblingDIE, RecurLevel + 1); /* recur others */
        };
    }
    
    return;
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

static src_file *
FindSourceFile(char *Path)
{
    src_file *Result = 0x0;
    
    for(u32 I = 0; I < SourceFilesCount; I++)
    {
        if(StringsMatch(Path, SourceFiles[I].Path))
        {
            Result = &SourceFiles[I];
            break;
        }
    }
    
    return Result;
}

static src_file *
PushSourceFile(char *Path)
{
    src_file *Result = 0x0;
    
    Result = &SourceFiles[SourceFilesCount++];
    
    Result->Path = strdup(Path);
    Result->Content = DumpFile(Path);
    Result->LineCount = StringCountChar(Result->Content, '\n');
    
    return Result;
}

static src_file *
GetSourceFile(char *Path)
{
    src_file *Result = 0x0;
    
    Result = FindSourceFile(Path);
    
    if(!Result)
    {
        Result = PushSourceFile(Path);
    }
    
    return Result;
}

static void
ReadDwarf()
{
    i32 Fd = open(Debuger.DebugeeProgramPath, O_RDONLY);
    assert(Fd != -1);
    
    Dwarf_Debug Debug = 0;
    Dwarf_Handler ErrorHandle = 0;
    Dwarf_Ptr ErrorArg = 0;
    Dwarf_Error *Error  = 0;
    
    assert(dwarf_init(Fd, DW_DLC_READ, ErrorHandle, ErrorArg, &Debug, Error) == DW_DLV_OK);
    
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    
    i32 CUCount = 0;
    
    for(;;++CUCount) {
        // NOTE(mateusz): I don't know what it does
        //Dwarf_Die no_die = 0;
        Dwarf_Die CurrentDIE = 0;
        i32 Result = dwarf_next_cu_header(Debug, &CUHeaderLength,
                                          &Version, &AbbrevOffset, &AddressSize,
                                          &NextCUHeader, Error);
        
        assert(Result != DW_DLV_ERROR);
        if(Result  == DW_DLV_NO_ENTRY) {
            break;
        }
        
        /* The CU will have a single sibling, a cu_die. */
        Result = dwarf_siblingof(Debug, 0, &CurrentDIE, Error);
        assert(Result != DW_DLV_ERROR && Result != DW_DLV_NO_ENTRY);
        
        RecurForEachDIE(Debug, CurrentDIE, 0);
        
        dwarf_dealloc(Debug, CurrentDIE, DW_DLA_DIE);
    }
    
    assert(dwarf_finish(Debug, Error) == DW_DLV_OK);
}

static size_t
SearchDIEsForEntryPoint(Dwarf_Debug Debug, Dwarf_Die DIE, i32 RecurLevel = 0)
{
    Dwarf_Die CurrentDIE = DIE;
	Dwarf_Die SiblingDIE = DIE;
	Dwarf_Die ChildDIE = 0;
	Dwarf_Error Error = {};
    
    Dwarf_Half Tag = 0;
    Dwarf_Bool HasAttr = 0;
    Dwarf_Attribute Attribute = 0;
    i32 Result = dwarf_tag(CurrentDIE, &Tag, &Error);
    assert(Result == DW_DLV_OK);
    if(Tag == DW_TAG_subprogram)
    {
        assert(!dwarf_hasattr(CurrentDIE, DW_AT_name, &HasAttr, &Error));
        if(HasAttr)
        {
            Result = dwarf_attr(CurrentDIE, DW_AT_name, &Attribute, &Error);
            assert(Result == DW_DLV_OK);
            
            char *Name = 0x0;
            Result = dwarf_formstring(Attribute, &Name, &Error);
            assert(Result == DW_DLV_OK);
            
            if(strcmp(Name, "main") == 0)
            {
                assert(!dwarf_hasattr(CurrentDIE, DW_AT_low_pc, &HasAttr, &Error) && HasAttr);
                Result = dwarf_attr(CurrentDIE, DW_AT_low_pc, &Attribute, &Error);
                assert(Result == DW_DLV_OK);
                
                Dwarf_Addr LowPCAddress = 0;
                Result = dwarf_formaddr(Attribute, &LowPCAddress, &Error);
                assert(Result == DW_DLV_OK);
                
                return LowPCAddress;
            }
        }
    }
    else
    {
        Result = dwarf_child(CurrentDIE, &ChildDIE, &Error);
        
        size_t PossbileResult = 0;
        
        if(Result == DW_DLV_OK)
        { 
            PossbileResult = SearchDIEsForEntryPoint(Debug, ChildDIE, RecurLevel + 1);
            
            if(PossbileResult)
            {
                return PossbileResult;
            }
            
            SiblingDIE = ChildDIE;
            while(Result == DW_DLV_OK)
            {
                CurrentDIE = SiblingDIE;
                Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, &Error);
                PossbileResult = SearchDIEsForEntryPoint(Debug, SiblingDIE, RecurLevel + 1);
                
                if(PossbileResult)
                {
                    return PossbileResult;
                }
            };
        }
    }
    
    return 0x0;
}

static Dwarf_Attribute
DWARFGetAttrib(Dwarf_Die DIE, Dwarf_Half Tag)
{
	Dwarf_Error Error = {};
    Dwarf_Bool HasAttr = 0;
    Dwarf_Attribute Attribute = 0;
    
    assert(dwarf_hasattr(DIE, Tag, &HasAttr, &Error) == DW_DLV_OK);
    assert(dwarf_attr(DIE, Tag, &Attribute, &Error) == DW_DLV_OK);
    
    return Attribute;
}

static void
RecurForEachDIEFunctions(Dwarf_Debug Debug, Dwarf_Die DIE, i32 RecurLevel = 0)
{
    Dwarf_Die CurrentDIE = DIE;
	Dwarf_Die SiblingDIE = DIE;
	Dwarf_Die ChildDIE = 0;
	Dwarf_Error Error = {};
    
    Dwarf_Half Tag = 0;
    Dwarf_Bool HasAttr = 0;
    i32 Result = dwarf_tag(CurrentDIE, &Tag, &Error);
    assert(Result == DW_DLV_OK);
    if(Tag == DW_TAG_subprogram)
    {
        dwarf_function *Func = &DWFunctions[DWFunctionsCount++];
        
        Dwarf_Attribute Attribute = DWARFGetAttrib(CurrentDIE, DW_AT_name);
        
        char *Name = 0x0;
        assert(dwarf_formstring(Attribute, &Name, &Error) == DW_DLV_OK);
        Func->Name = strdup(Name);
        
        assert(dwarf_hasattr(CurrentDIE, DW_AT_low_pc, &HasAttr, &Error) == DW_DLV_OK);
        if(HasAttr)
        {
            assert(dwarf_lowpc(CurrentDIE, (Dwarf_Addr *)&Func->LowPC, &Error) == DW_DLV_OK);
            
            Dwarf_Half Form = 0;
            Dwarf_Form_Class FormClass = {};
            assert(dwarf_highpc_b(CurrentDIE, (Dwarf_Addr *)&Func->HighPC,
                                  &Form, &FormClass, &Error) == DW_DLV_OK);
            if(FormClass == DW_FORM_CLASS_CONSTANT)
            {
                Func->HighPC += Func->LowPC;
            }
        }
    }
    else
    {
        Result = dwarf_child(CurrentDIE, &ChildDIE, &Error);
        
        size_t PossbileResult = 0;
        
        if(Result == DW_DLV_OK)
        { 
            RecurForEachDIEFunctions(Debug, ChildDIE, RecurLevel + 1);
            
            SiblingDIE = ChildDIE;
            while(true)
            {
                CurrentDIE = SiblingDIE;
                Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, &Error);
                if(Result == DW_DLV_OK)
                {
                    RecurForEachDIEFunctions(Debug, SiblingDIE, RecurLevel + 1);
                }
                else
                {
                    break;
                }
            };
        }
    }
}

static void
ReadDwarfFunctions()
{
    i32 Fd = open(Debuger.DebugeeProgramPath, O_RDONLY);
    assert(Fd != -1);
    
    Dwarf_Debug Debug = 0;
    Dwarf_Handler ErrorHandle = 0;
    Dwarf_Ptr ErrorArg = 0;
    Dwarf_Error *Error  = 0;
    
    assert(dwarf_init(Fd, DW_DLC_READ, ErrorHandle, ErrorArg, &Debug, Error) == DW_DLV_OK);
    
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    
    i32 CUCount = 0;
    
    for(;;++CUCount) {
        // NOTE(mateusz): I don't know what it does
        i32 Result = dwarf_next_cu_header(Debug, &CUHeaderLength,
                                          &Version, &AbbrevOffset, &AddressSize,
                                          &NextCUHeader, Error);
        
        assert(Result != DW_DLV_ERROR);
        if(Result  == DW_DLV_NO_ENTRY) {
            break;
        }
        
        /* The CU will have a single sibling, a cu_die. */
        Dwarf_Die CurrentDIE = 0;
        Result = dwarf_siblingof(Debug, 0, &CurrentDIE, Error);
        assert(Result != DW_DLV_ERROR && Result != DW_DLV_NO_ENTRY);
        RecurForEachDIEFunctions(Debug, CurrentDIE);
    }
    
    assert(dwarf_finish(Debug, Error) == DW_DLV_OK);
}

static address_range
AddressRangeCurrentAndNextLine()
{
    address_range Result = {};
    
    di_src_line *Current = LineTableFindByAddress(Regs.rip);
    for(i32 I = 0; I < DWLineEntriesCount; I++)
    {
        if(DWLineTable[I].Address == Current->Address)
        {
            for(;;I++)
            {
                if(DWLineEntriesCount == I + 1)
                {
                    dwarf_function *Func = FindFunctionConfiningAddress(Current->Address);
                    Result.Start = Current->Address;
                    Result.End = Func->HighPC;
                    goto end;
                }
                else
                {
                    di_src_line *Next = &DWLineTable[I];
                    if(Next->LineNum != Current->LineNum)
                    {
                        Result = LineAddressRangeBetween(Current, Next);
                        goto end;
                    }
                }
            }
        }
    }
    end:;
    
    
    return Result;
}

static size_t
FindEntryPointAddress()
{
    i32 Fd = open(Debuger.DebugeeProgramPath, O_RDONLY);
    assert(Fd != -1);
    
    Dwarf_Debug Debug = 0;
    Dwarf_Handler ErrorHandle = 0;
    Dwarf_Ptr ErrorArg = 0;
    Dwarf_Error *Error  = 0;
    
    assert(dwarf_init(Fd, DW_DLC_READ, ErrorHandle, ErrorArg, &Debug, Error) == DW_DLV_OK);
    
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    
    i32 CUCount = 0;
    
    for(;;++CUCount) {
        // NOTE(mateusz): I don't know what it does
        i32 Result = dwarf_next_cu_header(Debug, &CUHeaderLength,
                                          &Version, &AbbrevOffset, &AddressSize,
                                          &NextCUHeader, Error);
        
        assert(Result != DW_DLV_ERROR);
        if(Result  == DW_DLV_NO_ENTRY) {
            break;
        }
        
        /* The CU will have a single sibling, a cu_die. */
        Dwarf_Die CurrentDIE = 0;
        Result = dwarf_siblingof(Debug, 0, &CurrentDIE, Error);
        assert(Result != DW_DLV_ERROR && Result != DW_DLV_NO_ENTRY);
        
        size_t EntryPointAddress = SearchDIEsForEntryPoint(Debug, CurrentDIE, 0);
        if(EntryPointAddress)
        {
            return EntryPointAddress;
        }
    }
    
    assert(dwarf_finish(Debug, Error) == DW_DLV_OK);
    
    return 0x0;
}

static void
UpdateInfo()
{
    Regs = PeekRegisters(Debuger.DebugeePID);
    DisassembleAroundAddress(Regs.rip, Debuger.DebugeePID);
}

static void
DebugStart()
{
    glfwInit();
    GLFWwindow *Window = glfwCreateWindow(800, 600, "debag", NULL, NULL);
    glfwMakeContextCurrent(Window);
    glewInit();
    
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& IO = ImGui::GetIO(); (void)IO;
    ImGui::StyleColorsDark();
    
    ImGui_ImplGlfw_InitForOpenGL(Window, true);
    ImGui_ImplOpenGL3_Init("#version 130");
    
    glClearColor(0.5f, 0.5f, 0.5f, 1.0f);
    
    WaitForSignal(Debuger.DebugeePID);
    
    char TextBuff[64] = {};
    char TextBuff2[64] = {};
    
    Regs = PeekRegisters(Debuger.DebugeePID);
    
    ImGuiInputTextFlags ITFlags = 0;
    ITFlags |= ImGuiInputTextFlags_EnterReturnsTrue;
    
    assert(cs_open(CS_ARCH_X86, CS_MODE_64, &DisAsmHandle) == CS_ERR_OK);
    //cs_option(DisAsmHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT); 
    cs_option(DisAsmHandle, CS_OPT_DETAIL, CS_OPT_ON); 
    
    // NOTE(mateusz): For debug purpouses
    size_t EntryPointAddress = FindEntryPointAddress();
    assert(EntryPointAddress);
    
    breakpoint BP = BreakpointCreate(EntryPointAddress, Debuger.DebugeePID);
    BreakpointEnable(&BP);
    Breakpoints[BreakpointCount++] = BP;
    
    ReadDwarf();
    ReadDwarfFunctions();
    
    while(!glfwWindowShouldClose(Window))
    {
        glClear(GL_COLOR_BUFFER_BIT);
        
        ImGuiStartFrame();
        
        ImGui::Begin("Control window");
        
        if(ImGui::Button("Continue"))
        {
            ContinueProgram(Debuger.DebugeePID);
            
            UpdateInfo();
        }
        
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
            
            breakpoint BP = BreakpointCreate(EntryPointAddress, Debuger.DebugeePID);
            BreakpointEnable(&BP);
            Breakpoints[BreakpointCount++] = BP;
            
            UpdateInfo();
        }
        
        ImGui::InputText("tbr", TextBuff2, 64, ITFlags);
        ImGui::SameLine();
        
        if(ImGui::Button("BreakFunc"))
        {
            for(i32 I = 0; I < DWFunctionsCount; I++)
            {
                dwarf_function*Func = &DWFunctions[I];
                if(strcmp(TextBuff2, Func->Name) == 0)
                {
                    breakpoint BP = BreakpointCreate(EntryPointAddress, Debuger.DebugeePID);
                    BreakpointEnable(&BP);
                    Breakpoints[BreakpointCount++] = BP;
                }
            }
            
            UpdateInfo();
        }
        
        
        if(ImGui::Button("Single Step"))
        {
            StepInstruction(Debuger.DebugeePID);
            
            UpdateInfo();
        }
        
        if(ImGui::Button("Step"))
        {
            StepLine(Debuger.DebugeePID);
            
            UpdateInfo();
        }
        
        ImGui::SameLine();
        
        if(ImGui::Button("Next"))
        {
            address_range Range = AddressRangeCurrentAndNextLine();
            
            breakpoint TempBreakpoints[8] = {};
            u32 TempBreakpointsCount = 0;
            
            breakpoint BP = BreakpointCreate(Range.End, Debuger.DebugeePID);
            BreakpointEnable(&BP);
            TempBreakpoints[TempBreakpointsCount++] = BP;
            
            cs_insn *Instruction = 0x0;
            size_t CurrentAddress = Range.Start;
            
            while(CurrentAddress < Range.End)
            {
                size_t MachineWord = PeekDebugeeMemory(CurrentAddress, Debuger.DebugeePID);
                
                breakpoint *BP = BreakpointFind(CurrentAddress, Debuger.DebugeePID);
                if(BP)
                {
                    MachineWord = (MachineWord & ~0xff) | BP->SavedOpCode;
                }
                
                int Count = cs_disasm(DisAsmHandle, (const u8 *)&MachineWord, sizeof(MachineWord),
                                      CurrentAddress, 1, &Instruction);
                
                if(Count == 0) { break; }
                
                CurrentAddress += Instruction->size;
                
                inst_type Type = 0;
                if(Instruction->detail && Instruction->detail->groups_count > 0)
                {
                    for(i32 GroupIndex = 0;
                        GroupIndex < Instruction->detail->groups_count;
                        GroupIndex++)
                    {
                        switch(Instruction->detail->groups[GroupIndex])
                        {
                            case X86_GRP_JUMP:
                            {
                                Type |= INST_TYPE_JUMP;
                            }break;
                            case X86_GRP_CALL:
                            {
                                Type |= INST_TYPE_CALL;
                            }break;
                            case X86_GRP_RET:
                            {
                                Type |= INST_TYPE_RET;
                            }break;
                            case X86_GRP_BRANCH_RELATIVE:
                            {
                                Type |= INST_TYPE_RELATIVE_BRANCH;
                            }break;
                        }
                    }
                }
                
                if(Type & INST_TYPE_RET)
                {
                    size_t ReturnAddress = PeekDebugeeMemory(Regs.rbp + 8, Debuger.DebugeePID);
                    
                    breakpoint BP = BreakpointCreate(ReturnAddress, Debuger.DebugeePID);
                    BreakpointEnable(&BP);
                    TempBreakpoints[TempBreakpointsCount++] = BP;
                }
                
                if((Type & INST_TYPE_RELATIVE_BRANCH) && (Type & INST_TYPE_JUMP))
                {
                    // TODO(mateusz): It's a case of I'm not sure but I GUESS and if it blows
                    // up then I'll learn :+)
                    assert(Instruction->detail->x86.op_count == 1);
                    // TODO(mateusz): This is here just for me to remeber to implement jumps
                    // that are not specified by fixed memory locations but rather register
                    // values i.e. jump tables
                    assert(Instruction->detail->x86.operands[0].imm > 0x100);
                    
                    size_t OperandAddress = Instruction->detail->x86.operands[0].imm;
                    
                    breakpoint BP = BreakpointCreate(OperandAddress, Debuger.DebugeePID);
                    BreakpointEnable(&BP);
                    TempBreakpoints[TempBreakpointsCount++] = BP;
                }
                
                cs_free(Instruction, 1);
            }
            
            ContinueProgram(Debuger.DebugeePID);
            
            for(u32 I = 0; I < TempBreakpointsCount; I++)
            {
                BreakpointDisable(&TempBreakpoints[I]);
            }
            
            UpdateInfo();
        }
        
        ImGui::End();
        
        ImGui::Begin("x64 Registers");
        ImGuiShowRegisters(Regs);
        ImGui::End();
        
        ImGui::Begin("Listings");
        
        if(ImGui::BeginTabBar("Source and Disassebmly", ImGuiTabBarFlags_None))
        {
            if(ImGui::BeginTabItem("Source code"))
            {
                di_src_line *Line = LineTableFindByAddress(Regs.rip);
                
                if(Line)
                {
                    src_file *Src = GetSourceFile(Line->Path);
                    
                    char *LinePtr = Src->Content;
                    char *Prev = 0x0;
                    for(int I = 0; I < Src->LineCount + 1; I++)
                    {
                        Prev = LinePtr;
                        LinePtr = strchr(LinePtr, '\n') + 1;
                        u32 LineLength = (u64)LinePtr - (u64)Prev;
                        
                        // NOTE(mateusz): Lines are indexed from 1
                        if(Line->LineNum == I + 1)
                        {
                            ImGui::TextColored(CurrentLineColor, "%.*s",
                                               LineLength, Prev);
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
                for(int I = 0; I < DisasmInstCount; I++)
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
                ImGui::EndTabItem();
            }
            
            ImGui::EndTabBar();
        }
        
        ImGui::End();
        
        ImGuiEndFrame();
        
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
    
    i32 ProcessID = fork();
    
    // Child process
    if(ProcessID == 0)
    {
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, 0x0, 0x0);
        execl(Debuger.DebugeeProgramPath, Debuger.DebugeeProgramPath, 0x0);
    }
    else
    {
        Debuger.DebugeePID = ProcessID;
        DebugStart();
    }
    
    return 0;
}
#include <dbg.h>

static debugee
DebugeeCreate()
{
    debugee Result = { };

    Result.Arena = ArenaCreate(Kilobytes(4));

    // Query info about scalar register on the running processor
    // @Redundant: What if we do not have this?, can we just leave this as is?
    u32 EAX, EBX, ECX, EDX;
    assert(__get_cpuid_count(0x0d, 0x00, &EAX, &EBX, &ECX, &EDX));
    Result.XSaveSize = EBX;
    Result.XSaveBuffer = ArrayPush(&Result.Arena, u8, Result.XSaveSize);
    
    assert(__get_cpuid_count(0x0d, 0x02, &EAX, &EBX, &ECX, &EDX));
    Result.AVXOffset = EBX;
    
    // TODO(radomski): Does this even do anything???
    Result.Regs = DebugeePeekRegisters(&Result);

    return Result;
}

static void
DebugeeStart(debugee *Debugee)
{
    char BaseDir[128] = {};
    getcwd(BaseDir, sizeof(BaseDir));

    i32 ProcessID = fork();
    
    // Child process
    if(ProcessID == 0)
    {
        char *ProgramArgs[16] = {};
        u32 ArgsLen = 0;
        ProgramArgs[0] = Debugee->ProgramPath;
        StringToArgv(Debuger.ProgramArgs, &ProgramArgs[1], &ArgsLen);
        
        if(Debuger.PathToRunIn && strlen(Debuger.PathToRunIn) != 0)
        {
            i32 Result = chdir(Debuger.PathToRunIn);
            assert(Result == 0);
        }
        
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, 0x0, 0x0);
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        char *AbsolutePath = 0x0;
        if(Debugee->ProgramPath[0] == '/' || Debugee->ProgramPath[0] == '~')
        {
            AbsolutePath = Debugee->ProgramPath;
        }
        else
        {
            u32 Len1 = StringLength(Debugee->ProgramPath);
            u32 Len2 = StringLength(BaseDir);
            AbsolutePath = (char *)malloc(Len1 + Len2 + 16);

            sprintf(AbsolutePath, "%s/%s", BaseDir, Debugee->ProgramPath);
        }

        execv(AbsolutePath, ProgramArgs);
        free(AbsolutePath);
    }
    else
    {
        Debugee->PID = ProcessID;
        Debugee->Flags.Running = true;
        DebugeeWaitForSignal(Debugee);
        assert(chdir(BaseDir) == 0);
    }
}

static void
DebugeeKill(debugee *Debugee)
{
    ptrace(PTRACE_KILL, Debugee->PID, 0x0, 0x0);
    Debugee->Flags.Running = !Debugee->Flags.Running;
}

static void
DebugeeContinueOrStart(debugee *Debugee)
{
    if(IsFile(Debugee->ProgramPath))
    {
        GuiClearStatusText();
        
        //Continue or start program
        if(!Debugee->Flags.Running)
        {
            DebugeeStart(Debugee);
            
            Debugee->LoadAddress = DebugeeGetLoadAddress(Debugee);
            LOG_MAIN("LoadAddress = %lx\n", Debugee->LoadAddress);
            Debugee->Flags.PIE = DwarfIsExectuablePIE();
            
            DwarfRead();
            
            Debuger.UnwindRemoteArg = _UPT_create(Debugee->PID);

            BreakAtMain();
        }
    
        DebugeeContinueProgram(Debugee);
        DebugerUpdateTransient(&Debuger);
    }
    else
    {
        if(StringEmpty(Debugee->ProgramPath))
        {
            GuiSetStatusText("No program path given");
        }
        else
        {
            char Buff[2*PATH_MAX] = {};

            sprintf(Buff, "File at [%s] does not exist", Debugee->ProgramPath);

            GuiSetStatusText(Buff);
        }
    }
}

static void
DebugeeRestart(debugee *Debugee)
{
    if(Debugee->Flags.Running)
    {
        DebugeeKill(Debugee);
        DebugerDeallocTransient(&Debuger);

        DebugeeContinueOrStart(Debugee);
    }
}

static void
DebugeeWaitForSignal(debugee *Debugee)
{
    i32 WaitStatus;
    i32 Options = 0;
    i32 PID = Debugee->PID;
    waitpid(PID, &WaitStatus, Options);
    
    if(WIFEXITED(WaitStatus))
    {
        GuiSetStatusText("Program finished it's execution");
        Debugee->Flags.Running = !Debugee->Flags.Running;
        DebugerDeallocTransient(&Debuger);
    }
    
    siginfo_t SigInfo;
    ptrace(PTRACE_GETSIGINFO, PID, nullptr, &SigInfo);
    
    if(SigInfo.si_signo == SIGTRAP)
    {
        switch (SigInfo.si_code)
        {
            case SI_KERNEL:
            case TRAP_BRKPT:
            {
                Debugee->Regs = DebugeePeekRegisters(Debugee);
                Debugee->Regs.RIP -= 1;
                DebugeeSetRegisters(Debugee, Debugee->Regs);
                return;
            }break;
            case TRAP_TRACE:
            {
            }break;
            default:
            {
            }break;
        }
    }
    else if(SigInfo.si_signo == SIGSEGV)
    {
        GuiSetStatusText("Program seg faulted");
        DebugeeKill(Debugee);
        DebugerDeallocTransient(&Debuger);
    }
    else if(SigInfo.si_signo == SIGABRT)
    {
        DebugeeKill(Debugee);
        GuiSetStatusText("Program aborted");
        DebugerDeallocTransient(&Debuger);
    }
    else
    {
        // TODO(radomski): Logging, sane data route
        // LOG_FLOW("Unhandled signal = [%s]", strsignal(SigInfo.si_signo));
    }
}

static void
DebugeeToNextLine(debugee *Debugee, bool StepIntoFunctions)
{
    address_range Range = DwarfGetAddressRangeUntilNextLine(DebugeeGetProgramCounter(Debugee));
    // TODO(radomski): Logging, sane data route
    // LOG_FLOW("Regs.RIP = %lX, Range.Start = %lX, Range.End = %lX\n", DebugeeGetProgramCounter(), Range.Start, Range.End);

    BreakAtCurcialInstrsInRange(Range, StepIntoFunctions, TempBreakpoints, &TempBreakpointsCount);
    
    DebugeeContinueProgram(Debugee);
    
    // TODO(radomski): Logging, sane data route
    // LOG_FLOW("TempBreakpointsCount = %d\n", TempBreakpointsCount);
    for(u32 I = 0; I < TempBreakpointsCount; I++)
    {
        // TODO(radomski): Logging, sane data route
        // LOG_FLOW("Breakpoint[%d] at %lX\n", I, TempBreakpoints[I].Address);
        BreakpointDisable(&TempBreakpoints[I]);
    }

    memset(TempBreakpoints, 0, sizeof(TempBreakpoints[0]) * TempBreakpointsCount);
    TempBreakpointsCount = 0;
    
    Debugee->Flags.Steped = true;
}

static void
DebugeeStepInstruction(debugee *Debugee)
{
    i32 PID = Debugee->PID;
    breakpoint *BP = BreakpointFind(DebugeeGetProgramCounter(Debugee));
    bool EnabledAtEntry = BreakpointEnabled(BP);
    if(BP && EnabledAtEntry && !BP->State.ExectuedSavedOpCode) { BreakpointDisable(BP); }
    
    ptrace(PTRACE_SINGLESTEP, PID, 0x0, 0x0);
    DebugeeWaitForSignal(Debugee);
    
    if(BP && EnabledAtEntry && !BP->State.ExectuedSavedOpCode) { BreakpointEnable(BP); }
    if(BP) { BP->State.ExectuedSavedOpCode = !BP->State.ExectuedSavedOpCode; }
    
    Debugee->Regs = DebugeePeekRegisters(Debugee);

    Debugee->Flags.Steped = true;
}

static void
DebugeeToNextInstruction(debugee *Debugee, bool StepIntoFunctions)
{
    size_t PC = DebugeeGetProgramCounter(Debugee);

    size_t InstrInMemory[2] = {};
    
    breakpoint *BP = BreakpointFind(PC);
    if(BP)
    {
        InstrInMemory[0] = BP->SavedOpCodes;
    }
    else
    {
        InstrInMemory[0] = DebugeePeekMemory(Debugee, PC);
    }
    
    InstrInMemory[1] = DebugeePeekMemory(Debugee, PC + 8);
    
    cs_insn *Instruction = 0x0;
    u32 Count = cs_disasm(DisAsmHandle, (u8 *)InstrInMemory, sizeof(InstrInMemory), PC, 1, &Instruction);
    assert(Count);

    inst_type Type = AsmInstructionGetType(Instruction);

    if(Type & INST_TYPE_CALL)
    {
        if(StepIntoFunctions)
        {
            assert(Instruction->detail->x86.op_count == 1);
            
            size_t JumpAddress = 0x0;
            auto Operand = &Instruction->detail->x86.operands[0];
            if(Operand->type == X86_OP_IMM)
            {
                JumpAddress = Operand->imm;
            }
            else if(Operand->type == X86_OP_REG)
            {
                u32 ABINumber = CapstoneRegisterToABINumber(Operand->reg);
                JumpAddress = RegisterGetByABINumber(Debugee->Regs, ABINumber);
            }
            else
            {
                assert(false && "A jmp instruction that is not imm and not a reg.");
            }

            bool AddressInAnyCompileUnit = DwarfFindCompileUnitByAddress(JumpAddress) != 0x0;
            if(AddressInAnyCompileUnit)
            {
                DebugeeStepInstruction(Debugee);
            }
            else
            {
                size_t NextInstrAddress = PC + Instruction->size;

                breakpoint BP = BreakpointCreate(NextInstrAddress);
                BreakpointEnable(&BP);

                DebugeeContinueProgram(Debugee);

                BreakpointDisable(&BP);
            }
        }
        else
        {
            size_t NextInstrAddress = PC + Instruction->size;
        
            breakpoint BP = BreakpointCreate(NextInstrAddress);
            BreakpointEnable(&BP);

            DebugeeContinueProgram(Debugee);

            BreakpointDisable(&BP);
        }
    }
    else if(Type & INST_TYPE_RET)
    {
        size_t ReturnAddress = DebugeeGetReturnAddress(Debugee, PC);

        bool AddressInAnyCompileUnit = DwarfFindCompileUnitByAddress(ReturnAddress) != 0x0;
        if(AddressInAnyCompileUnit)
        {
            DebugeeStepInstruction(Debugee);
        }
        else
        {
            DebugeeContinueProgram(Debugee);
        }
    }
    else
    {
        DebugeeStepInstruction(Debugee);
    }

    cs_free(Instruction, 1);
    
    Debugee->Flags.Steped = true;
}

static void
DebugeeContinueProgram(debugee *Debugee)
{
    if(BreakpointCount > 0 || TempBreakpointsCount > 0)
    {
        size_t OldPC = DebugeeGetProgramCounter(Debugee);
        DebugeeStepInstruction(Debugee);
        
        breakpoint *BP = BreakpointFind(OldPC);
        if(BreakpointEnabled(BP))
        {
            BP->State.ExectuedSavedOpCode = false;
        }
    }
    
    Debugee->Flags.Steped = true;

    Debugee->Regs = DebugeePeekRegisters(Debugee);
    breakpoint *BP = 0x0;
    if((BP = BreakpointFind(DebugeeGetProgramCounter(Debugee))) && BreakpointEnabled(BP))
    {
        return;
    }
    else
    {
        i32 PID = Debugee->PID;
        ptrace(PTRACE_CONT, PID, 0x0, 0x0);
        DebugeeWaitForSignal(Debugee);
    }
    
    size_t PC = DebugeeGetProgramCounter(Debugee);
    di_function *Func = DwarfFindFunctionByAddress(PC);

    if(Func && PC == Func->FuncLexScope.LowPC)
    {
        assert(BreakpointCount > 0 || TempBreakpointsCount > 0);
        breakpoint *BP = BreakpointFind(DebugeeGetProgramCounter(Debugee));
        
        if(BP)
        {
            u8 PushRBP[] = { 0x55 };
            u8 MovRBPRSP[] = { 0x48, 0x89, 0xe5 };

            u8 *MemoryAtPC = (u8 *)&BP->SavedOpCodes;

            if(memcmp(MemoryAtPC, PushRBP, sizeof(PushRBP)) == 0 &&
               memcmp(MemoryAtPC + sizeof(PushRBP), MovRBPRSP, sizeof(MovRBPRSP)) == 0)
            {
                // Now we will step one line to go over all of the init stuff
                DebugeeToNextLine(Debugee, false);
            }
        }
    }
}

static void
DebugeeStepOutOfFunction(debugee *Debugee)
{
    di_function *Func = DwarfFindFunctionByAddress(DebugeeGetProgramCounter(Debugee));

    DebugeeToNextLine(Debugee, false);
    DebugerUpdateTransient(&Debuger);

    size_t PC = DebugeeGetProgramCounter(Debugee);
    if(DwarfAddressConfinedByFunction(Func, PC))
    {
        size_t PC = DebugeeGetProgramCounter(Debugee);
        size_t ReturnAddress = DebugeeGetReturnAddress(Debugee, PC);
        bool OwnBreakpoint = false;
        breakpoint BP = {};

        if(!BreakpointFind(ReturnAddress))
        {
            BP = BreakpointCreate(ReturnAddress);
            BreakpointEnable(&BP);
            OwnBreakpoint = true;
        }
    
        DebugeeContinueProgram(Debugee);
        if(OwnBreakpoint)
        {
            BreakpointDisable(&BP);
        }
    }
    
    Debugee->Flags.Steped = true;
}

static x64_registers
DebugeePeekRegisters(debugee *Debugee)
{
    x64_registers Result = {};
    
    user_regs_struct USR = {};
    ptrace(PTRACE_GETREGS, Debugee->PID, 0x0, &USR);
    
    Result = RegistersFromUSR(USR);
    return Result;
}

static void
DebugeePeekXSave(debugee *Debugee)
{
    struct iovec IO = { Debugee->XSaveBuffer, Debugee->XSaveSize };
    ptrace(PTRACE_GETREGSET, Debugee->PID, NT_X86_XSTATE, &IO);

    u64 XStateBV = *((u64 *)(&Debugee->XSaveBuffer[512]));

    Debugee->RegsFlags.EnabledSSE = (XStateBV & (1 << 1)) ? 1 : 0;
    Debugee->RegsFlags.EnabledAVX = (XStateBV & (1 << 2)) ? 1 : 0;
}

static void
DebugeeSetRegisters(debugee *Debugee, x64_registers Regs)
{
    user_regs_struct USR = RegistersToUSR(Regs);
    ptrace(PTRACE_SETREGS, Debugee->PID, 0x0, &USR);
}

static inline size_t
DebugeeGetProgramCounter(debugee *Debugee)
{
    return Debugee->Regs.RIP;
}

static inline size_t
DebugeeGetReturnAddress(debugee *Debugee, size_t Address)
{
    size_t CFA = DwarfGetCanonicalFrameAddress(Address);
    size_t MachineWord = DebugeePeekMemory(Debugee, CFA - 8);

    return MachineWord;
}

static void
DebugeePokeMemory(debugee *Debugee, size_t Address, size_t MachineWord)
{
    ptrace(PTRACE_POKEDATA, Debugee->PID, Address, MachineWord);
}

static size_t
DebugeePeekMemory(debugee *Debugee, size_t Address)
{
    size_t MachineWord = 0;

    MachineWord = ptrace(PTRACE_PEEKDATA, Debugee->PID, Address, 0x0);
    
    return MachineWord;
}

// Out array has be a multiple of 8 sized 
static void
DebugeePeekMemoryArray(debugee *Debugee, size_t StartAddress, u32 EndAddress, u8 *OutArray, u32 BytesToRead)
{
    size_t *MemoryPtr = (size_t *)OutArray;
    
    size_t TempAddress = StartAddress;
    for(u32 I = 0; I < BytesToRead / sizeof(size_t); I++)
    {
        *MemoryPtr = DebugeePeekMemory(Debugee, TempAddress);
        MemoryPtr += 1;
        TempAddress += 8;
        if(TempAddress >= EndAddress)
        {
            break;
        }
    }
}

static size_t
DebugeeGetLoadAddress(debugee *Debugee)
{
    i32 PID = Debugee->PID;

    char Path[PATH_MAX] = {};
    sprintf(Path, "/proc/%d/maps", PID);
    LOG_DWARF("Load Path is %s\n", Path);
    
    char AddrStr[16] = {};
    FILE *FileHandle = fopen(Path, "r");
    assert(FileHandle);
    fread(AddrStr, sizeof(AddrStr), 1, FileHandle);
    
    u32 Length = sizeof(AddrStr);
    for(u32 I = 0; I < sizeof(AddrStr); I++)
    {
        if(AddrStr[I] == '-')
        {
            Length = I;
            break;
        }
    }
    
    size_t Result = 0x0;
    
    for(u32 I = 0; I < Length; I++)
    {
        size_t HexToDec = (AddrStr[I] - '0') > 10 ? (AddrStr[I] - 'a') + 10 : (AddrStr[I] - '0');
        Result += HexToDec << (4 * (Length - I - 1));
    }
    
    return Result;
}

static void
DebugeeBuildBacktrace(debugee *Debugee)
{
    if(Debuger.Unwind.FuncList.Head)
    {
        unwind_functions_bucket *Bucket = Debuger.Unwind.FuncList.Head;

        while(Bucket)
        {
            unwind_functions_bucket *ToDelete = Bucket;
            Bucket = Bucket->Next;

            free(ToDelete);
        }
        Debuger.Unwind.FuncList.Head = 0x0;
    }
    
    unw_context_t UnwindCtx = {};
    unw_getcontext(&UnwindCtx);
    unw_addr_space_t UnwindAddressSpace = unw_create_addr_space(&_UPT_accessors, __LITTLE_ENDIAN);
    assert(UnwindAddressSpace);
    
    unw_cursor_t UnwindCursor = {};
    assert(unw_init_remote(&UnwindCursor, UnwindAddressSpace, Debuger.UnwindRemoteArg) == 0);

    Debuger.Unwind.Address = DebugeeGetProgramCounter(Debugee);
    
    di_function *Func = DwarfFindFunctionByAddress(DebugeeGetProgramCounter(Debugee));
    if(!Func) { return; }

    unwind_functions_bucket *Bucket = (unwind_functions_bucket *)calloc(1, sizeof(unwind_functions_bucket));

    if(!Gui->Transient.FuncRepresentation)
    {
        GuiBuildFunctionRepresentation();
    }
    
    unwind_function UnwoundFunction = 0x0;
    for(u32 I = 0; I < Gui->Transient.FuncRepresentationCount; I++)
    {
        if(Gui->Transient.FuncRepresentation[I].ActualFunction == Func)
        {
            UnwoundFunction = &Gui->Transient.FuncRepresentation[I];
        }
    }
    assert(UnwoundFunction);
    Bucket->Functions[Bucket->Count++] = UnwoundFunction;
    
    while(unw_step(&UnwindCursor) > 0)
    {
        unw_word_t StackPointer = 0x0;
        unw_get_reg(&UnwindCursor, UNW_REG_SP, &StackPointer);
        size_t ReturnAddress = DebugeePeekMemory(Debugee, StackPointer - 8);

        di_function *Func = DwarfFindFunctionByAddress(ReturnAddress);
        if(!Func) { break; }

        unwind_function UnwoundFunction = 0x0;
        for(u32 I = 0; I < Gui->Transient.FuncRepresentationCount; I++)
        {
            if(Gui->Transient.FuncRepresentation[I].ActualFunction == Func)
            {
                UnwoundFunction = &Gui->Transient.FuncRepresentation[I];
            }
        }
        assert(UnwoundFunction);

        if(Bucket->Count >= ARRAY_LENGTH(Bucket->Functions))
        {
            SLL_QUEUE_PUSH(Debuger.Unwind.FuncList.Head, Debuger.Unwind.FuncList.Tail, Bucket);
            Bucket = (unwind_functions_bucket *)calloc(1, sizeof(unwind_functions_bucket));
        }
        
        Bucket->Functions[Bucket->Count++] = UnwoundFunction;
    } 

    SLL_QUEUE_PUSH(Debuger.Unwind.FuncList.Head, Debuger.Unwind.FuncList.Tail, Bucket);
}

static void
DisassembleAroundAddress(address_range AddrRange)
{
    LOG_MAIN("AddrRange = %lx - %lx\n", AddrRange.Start, AddrRange.End);
    u32 InstCount = 0;
    cs_option(DisAsmHandle, CS_OPT_DETAIL, CS_OPT_OFF); 

    cs_insn *Instruction = {};
    size_t InstructionAddress = AddrRange.Start;
    while(InstructionAddress < AddrRange.End)
    {
        u8 InstrInMemory[16] = {};
        DebugeePeekMemoryArray(&Debugee, InstructionAddress, AddrRange.End, InstrInMemory, sizeof(InstrInMemory));
        
        {
            breakpoint *BP = 0x0; ;
            if((BP = BreakpointFind(InstructionAddress)) && BreakpointEnabled(BP))
            {
                InstrInMemory[0] = (u8)(BP->SavedOpCodes & 0xff);
            }
        }
        
        int Count = cs_disasm(DisAsmHandle, InstrInMemory, sizeof(InstrInMemory),
                              InstructionAddress, 1, &Instruction);
        
        if(Count == 0) { break; }

        InstCount++;
        InstructionAddress += Instruction->size;
        
        cs_free(Instruction, 1);
    }
    cs_option(DisAsmHandle, CS_OPT_DETAIL, CS_OPT_ON);

    DisasmInstCount = 0;
    
    InstructionAddress = AddrRange.Start;
    ArenaClear(&DisasmArena);
    DisasmInst = ArrayPush(&DisasmArena, disasm_inst, InstCount);
    for(u32 I = 0; I < InstCount; I++)
    {
        u8 InstrInMemory[16] = {};
        DebugeePeekMemoryArray(&Debugee, InstructionAddress, AddrRange.End, InstrInMemory, sizeof(InstrInMemory));
        
        {
            breakpoint *BP = 0x0; ;
            if((BP = BreakpointFind(InstructionAddress)) && BreakpointEnabled(BP))
            {
                InstrInMemory[0] = (u8)(BP->SavedOpCodes & 0xff);
            }
        }
        
        int Count = cs_disasm(DisAsmHandle, InstrInMemory, sizeof(InstrInMemory),
                              InstructionAddress, 1, &Instruction);
        
        if(Count == 0) { break; }
        
        DisasmInst[I].Address = InstructionAddress;
        InstructionAddress += Instruction->size;
        
        DisasmInst[I].Mnemonic = StringDuplicate(&DisasmArena, Instruction->mnemonic);
        DisasmInst[I].Operation = StringDuplicate(&DisasmArena, Instruction->op_str);
        DisasmInstCount++;
        
        cs_free(Instruction, 1);
    }
}

static dbg
DebugerCreate()
{
    dbg Result = { };

    // Check if we have scalar register on the running processor
    u32 EAX, EBX, ECX, EDX;
    assert(__get_cpuid(0x01, &EAX, &EBX, &ECX, &EDX));

    Result.RegsFlags.HasMMX = EDX & bit_MMX ? 1 : 0;
    Result.RegsFlags.HasSSE = ECX & bit_SSE ? 1 : 0;
    Result.RegsFlags.HasAVX = ECX & bit_AVX ? 1 : 0;

    return Result;
}

static void
DebugerUpdateTransient(dbg *Debuger)
{
    (void)(Debuger);
    Debugee.Regs = DebugeePeekRegisters(&Debugee);
    DebugeePeekXSave(&Debugee);
    
    di_function *Func = DwarfFindFunctionByAddress(DebugeeGetProgramCounter(&Debugee));
    if(Func)
    {
        assert(Func->FuncLexScope.RangesCount == 0);
        address_range LexScopeRange = {};
        LexScopeRange.Start = Func->FuncLexScope.LowPC;
        LexScopeRange.End = Func->FuncLexScope.HighPC;
        LOG_MAIN("LexScope of %s is %lx-%lx\n", Func->Name, LexScopeRange.Start, LexScopeRange.End);
        
        DisassembleAroundAddress(LexScopeRange);
    }
}

static void
DebugerDeallocTransient(dbg *Debuger)
{
    DwarfClearAll();

#if CLEAR_BREAKPOINTS
    memset(Breakpoints, 0, sizeof(breakpoint) * BreakpointCount);
    BreakpointCount = 0;
#endif

    _UPT_destroy(Debuger->UnwindRemoteArg);
    
    ArenaDestroy(&Debugee.Arena);

	ArenaDestroy(&Gui->Transient.RepresentationArena);
	ArenaDestroy(&Gui->Transient.WatchArena);
	Gui->Transient = {};
	Gui->Transient.RepresentationArena = ArenaCreate(Kilobytes(4));
	Gui->Transient.WatchArena = ArenaCreate(Kilobytes(4));
}

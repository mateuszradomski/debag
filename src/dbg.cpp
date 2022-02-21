#include <dbg.h>

static void
DebugeeStart()
{
    char BaseDir[128] = {};
    getcwd(BaseDir, sizeof(BaseDir));

    i32 ProcessID = fork();
    
    // Child process
    if(ProcessID == 0)
    {
        char *ProgramArgs[16] = {};
        u32 ArgsLen = 0;
        ProgramArgs[0] = Debugee.ProgramPath;
        StringToArgv(Debuger.ProgramArgs, &ProgramArgs[1], &ArgsLen);
        
        if(Debuger.PathToRunIn && strlen(Debuger.PathToRunIn) != 0)
        {
            i32 Result = chdir(Debuger.PathToRunIn);
            assert(Result == 0);
            
//            char CWDStr[128] = {};
//            LOG_MAIN("child getcwd() = [%s]\n", getcwd(CWDStr, sizeof(CWDStr)));
        }
        
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, 0x0, 0x0);
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        char *AbsolutePath = 0x0;
        if(Debugee.ProgramPath[0] == '/' || Debugee.ProgramPath[0] == '~')
        {
            AbsolutePath = Debugee.ProgramPath;
        }
        else
        {
            u32 Len1 = StringLength(Debugee.ProgramPath);
            u32 Len2 = StringLength(BaseDir);
            AbsolutePath = (char *)malloc(Len1 + Len2 + 16);

            sprintf(AbsolutePath, "%s/%s", BaseDir, Debugee.ProgramPath);
        }

        execv(AbsolutePath, ProgramArgs);
        free(AbsolutePath);
    }
    else
    {
        Debugee.PID = ProcessID;
        Debugee.Flags.Running = true;
        DebugeeWaitForSignal();
        assert(chdir(BaseDir) == 0);
    }
}

static void
DebugeeKill()
{
    ptrace(PTRACE_KILL, Debugee.PID, 0x0, 0x0);
    Debugee.Flags.Running = !Debugee.Flags.Running;
}

static void
DebugeeContinueOrStart()
{
    if(IsFile(Debugee.ProgramPath))
    {
        GuiClearStatusText();
        
        //Continue or start program
        if(!Debugee.Flags.Running)
        {
            DebugeeStart();
            
            Debugee.LoadAddress = DebugeeGetLoadAddress(Debugee.PID);
            LOG_MAIN("LoadAddress = %lx\n", Debugee.LoadAddress);
            Debugee.Flags.PIE = DwarfIsExectuablePIE();
            
            DwarfRead();
            
            Debuger.UnwindRemoteArg = _UPT_create(Debugee.PID);

            BreakAtMain();
        }
    
        DebugeeContinueProgram();
        DebugerUpdateTransient();
    }
    else
    {
        if(StringEmpty(Debugee.ProgramPath))
        {
            GuiSetStatusText("No program path given");
        }
        else
        {
            char Buff[2*PATH_MAX] = {};

            sprintf(Buff, "File at [%s] does not exist", Debugee.ProgramPath);

            GuiSetStatusText(Buff);
        }
    }
}

static void
DebugeeRestart()
{
    if(Debugee.Flags.Running)
    {
        DebugeeKill();
        DebugerDeallocTransient();

        DebugeeContinueOrStart();
    }
}

static void
DebugeeWaitForSignal()
{
    i32 WaitStatus;
    i32 Options = 0;
    i32 PID = Debugee.PID;
    waitpid(PID, &WaitStatus, Options);
    
    if(WIFEXITED(WaitStatus))
    {
        GuiSetStatusText("Program finished it's execution");
        Debugee.Flags.Running = !Debugee.Flags.Running;
        DebugerDeallocTransient();
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
                Debugee.Regs = DebugeePeekRegisters();
                Debugee.Regs.RIP -= 1;
                DebugeeSetRegisters(Debugee.Regs);
                //auto offset_pc = offset_load_address(get_pc()); //rember to offset the pc for querying DWARF
                //auto line_entry = get_line_entry_from_pc(offset_pc);
                //print_source(line_entry->file->path, line_entry->line);
                return;
            }break;
            //this will be set if the signal was sent by single stepping
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
        DebugeeKill();
        DebugerDeallocTransient();
    }
    else if(SigInfo.si_signo == SIGABRT)
    {
        DebugeeKill();
        GuiSetStatusText("Program aborted");
        DebugerDeallocTransient();
    }
    else
    {
        // TODO(radomski): Logging, sane data route
        // LOG_FLOW("Unhandled signal = [%s]", strsignal(SigInfo.si_signo));
    }
}

static void
DebugeeToNextLine(bool StepIntoFunctions)
{
    address_range Range = DwarfGetAddressRangeUntilNextLine(DebugeeGetProgramCounter());
    // TODO(radomski): Logging, sane data route
    // LOG_FLOW("Regs.RIP = %lX, Range.Start = %lX, Range.End = %lX\n", DebugeeGetProgramCounter(), Range.Start, Range.End);

    BreakAtCurcialInstrsInRange(Range, StepIntoFunctions, TempBreakpoints, &TempBreakpointsCount);
    
    DebugeeContinueProgram();
    
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
    
    Debugee.Flags.Steped = true;
}

static void
DebugeeStepInstruction()
{
    i32 PID = Debugee.PID;
    breakpoint *BP = BreakpointFind(DebugeeGetProgramCounter());
    bool EnabledAtEntry = BreakpointEnabled(BP);
    if(BP && EnabledAtEntry && !BP->State.ExectuedSavedOpCode) { BreakpointDisable(BP); }
    
    ptrace(PTRACE_SINGLESTEP, PID, 0x0, 0x0);
    DebugeeWaitForSignal();
    
    if(BP && EnabledAtEntry && !BP->State.ExectuedSavedOpCode) { BreakpointEnable(BP); }
    if(BP) { BP->State.ExectuedSavedOpCode = !BP->State.ExectuedSavedOpCode; }
    
    Debugee.Regs = DebugeePeekRegisters();

    Debugee.Flags.Steped = true;
}

static void
DebugeeToNextInstruction(bool StepIntoFunctions)
{
    size_t PC = DebugeeGetProgramCounter();

    size_t InstrInMemory[2] = {};
    
    breakpoint *BP = BreakpointFind(PC);
    if(BP)
    {
        InstrInMemory[0] = BP->SavedOpCodes;
    }
    else
    {
        InstrInMemory[0] = DebugeePeekMemory(PC);
    }
    
    InstrInMemory[1] = DebugeePeekMemory(PC + 8);
    
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
                JumpAddress = RegisterGetByABINumber(Debugee.Regs, ABINumber);
            }
            else
            {
                assert(false && "A jmp instruction that is not imm and not a reg.");
            }

            bool AddressInAnyCompileUnit = DwarfFindCompileUnitByAddress(JumpAddress) != 0x0;
            if(AddressInAnyCompileUnit)
            {
                DebugeeStepInstruction();
            }
            else
            {
                size_t NextInstrAddress = PC + Instruction->size;

                breakpoint BP = BreakpointCreate(NextInstrAddress);
                BreakpointEnable(&BP);

                DebugeeContinueProgram();

                BreakpointDisable(&BP);
            }
        }
        else
        {
            size_t NextInstrAddress = PC + Instruction->size;
        
            breakpoint BP = BreakpointCreate(NextInstrAddress);
            BreakpointEnable(&BP);

            DebugeeContinueProgram();

            BreakpointDisable(&BP);
        }
    }
    else if(Type & INST_TYPE_RET)
    {
        size_t ReturnAddress = DebugeeGetReturnAddress(PC);

        bool AddressInAnyCompileUnit = DwarfFindCompileUnitByAddress(ReturnAddress) != 0x0;
        if(AddressInAnyCompileUnit)
        {
            DebugeeStepInstruction();
        }
        else
        {
            DebugeeContinueProgram();
        }
    }
    else
    {
        DebugeeStepInstruction();
    }

    cs_free(Instruction, 1);
    
    Debugee.Flags.Steped = true;
}

static void
DebugeeContinueProgram()
{
    if(BreakpointCount > 0 || TempBreakpointsCount > 0)
    {
        size_t OldPC = DebugeeGetProgramCounter();
        DebugeeStepInstruction();
        
        breakpoint *BP = BreakpointFind(OldPC);
        if(BreakpointEnabled(BP))
        {
            BP->State.ExectuedSavedOpCode = false;
        }
    }
    
    Debugee.Flags.Steped = true;

    Debugee.Regs = DebugeePeekRegisters();
    breakpoint *BP = 0x0;
    if((BP = BreakpointFind(DebugeeGetProgramCounter())) && BreakpointEnabled(BP))
    {
        return;
    }
    else
    {
        i32 PID = Debugee.PID;
        ptrace(PTRACE_CONT, PID, 0x0, 0x0);
        DebugeeWaitForSignal();
    }
    
    size_t PC = DebugeeGetProgramCounter();
    di_function *Func = DwarfFindFunctionByAddress(PC);

    if(Func && PC == Func->FuncLexScope.LowPC)
    {
        assert(BreakpointCount > 0 || TempBreakpointsCount > 0);
        breakpoint *BP = BreakpointFind(DebugeeGetProgramCounter());
        
        if(BP)
        {
            u8 PushRBP[] = { 0x55 };
            u8 MovRBPRSP[] = { 0x48, 0x89, 0xe5 };

            u8 *MemoryAtPC = (u8 *)&BP->SavedOpCodes;

            if(memcmp(MemoryAtPC, PushRBP, sizeof(PushRBP)) == 0 &&
               memcmp(MemoryAtPC + sizeof(PushRBP), MovRBPRSP, sizeof(MovRBPRSP)) == 0)
            {
                // Now we will step one line to go over all of the init stuff
                DebugeeToNextLine(false);
            }
        }
    }
}

static void
DebugeeStepOutOfFunction()
{
    di_function *Func = DwarfFindFunctionByAddress(DebugeeGetProgramCounter());

    DebugeeToNextLine(false);
    DebugerUpdateTransient();

    size_t PC = DebugeeGetProgramCounter();
    if(DwarfAddressConfinedByFunction(Func, PC))
    {
        size_t ReturnAddress = DebugeeGetReturnAddress(DebugeeGetProgramCounter());
        bool OwnBreakpoint = false;
        breakpoint BP = {};

        if(!BreakpointFind(ReturnAddress))
        {
            BP = BreakpointCreate(ReturnAddress);
            BreakpointEnable(&BP);
            OwnBreakpoint = true;
        }
    
        DebugeeContinueProgram();
        if(OwnBreakpoint)
        {
            BreakpointDisable(&BP);
        }
    }
    
    Debugee.Flags.Steped = true;
}

static x64_registers
DebugeePeekRegisters()
{
    x64_registers Result = {};
    
    user_regs_struct USR = {};
    ptrace(PTRACE_GETREGS, Debugee.PID, 0x0, &USR);
    
    Result = RegistersFromUSR(USR);
    return Result;
}

static void
DebugeePeekXSave()
{
    struct iovec IO = { Debugee.XSaveBuffer, Debugee.XSaveSize };
    ptrace(PTRACE_GETREGSET, Debugee.PID, NT_X86_XSTATE, &IO);

    u64 XStateBV = *((u64 *)(&Debugee.XSaveBuffer[512]));

    Debugee.RegsFlags.EnabledSSE = (XStateBV & (1 << 1)) ? 1 : 0;
    Debugee.RegsFlags.EnabledAVX = (XStateBV & (1 << 2)) ? 1 : 0;
}

static void
DebugeeSetRegisters(x64_registers Regs)
{
    user_regs_struct USR = RegistersToUSR(Regs);
    ptrace(PTRACE_SETREGS, Debugee.PID, 0x0, &USR);
}

static inline size_t
DebugeeGetProgramCounter()
{
    return Debugee.Regs.RIP;
}

static inline size_t
DebugeeGetReturnAddress(size_t Address)
{
    size_t CFA = DwarfGetCanonicalFrameAddress(Address);
    size_t MachineWord = DebugeePeekMemory(CFA - 8);

    return MachineWord;
}

static void
DebugeePokeMemory(size_t Address, size_t MachineWord)
{
    ptrace(PTRACE_POKEDATA, Debugee.PID, Address, MachineWord);
}

static size_t
DebugeePeekMemory(size_t Address)
{
    size_t MachineWord = 0;

    MachineWord = ptrace(PTRACE_PEEKDATA, Debugee.PID, Address, 0x0);
    
    return MachineWord;
}

// Out array has be a multiple of 8 sized 
static void
DebugeePeekMemoryArray(size_t StartAddress, u32 EndAddress, u8 *OutArray, u32 BytesToRead)
{
    size_t *MemoryPtr = (size_t *)OutArray;
    
    size_t TempAddress = StartAddress;
    for(u32 I = 0; I < BytesToRead / sizeof(size_t); I++)
    {
        *MemoryPtr = DebugeePeekMemory(TempAddress);
        MemoryPtr += 1;
        TempAddress += 8;
        if(TempAddress >= EndAddress)
        {
            break;
        }
    }
}

static size_t
DebugeeGetLoadAddress(i32 DebugeePID)
{
    char Path[PATH_MAX] = {};
    sprintf(Path, "/proc/%d/maps", DebugeePID);
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
DebugeeBuildBacktrace()
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

    Debuger.Unwind.Address = DebugeeGetProgramCounter();
    
    di_function *Func = DwarfFindFunctionByAddress(DebugeeGetProgramCounter());
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
        size_t ReturnAddress = DebugeePeekMemory(StackPointer - 8);

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

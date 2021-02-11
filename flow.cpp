#ifdef DEBUG
#define LOG_FLOW(fmt, ...) if(Debuger.Log.FlowLogs) { printf(fmt, ##__VA_ARGS__); }
#else
#define LOG_FLOW(...) do { } while (0)
#endif

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
        LOG_FLOW("Unhandled signal = [%s]", strsignal(SigInfo.si_signo));
    }
}

static breakpoint *
BreakpointFind(size_t Address, breakpoint *BPs, u32 Count)
{
    for(u32 I = 0; I < Count; I++)
    {
        breakpoint *BP = &BPs[I];
        if(BP->Address == Address)
        {
            return BP;
        }
    }
    
    return 0x0;
}

static breakpoint *
BreakpointFind(size_t Address)
{
    breakpoint *Result = 0x0;
    
    Result = BreakpointFind(Address, Breakpoints, BreakpointCount);
    if(!Result)
    {
        Result = BreakpointFind(Address, TempBreakpoints, TempBreakpointsCount);
    }
    
    return Result;
}

static bool
BreakpointEnabled(breakpoint *BP)
{
    if(BP && BP->State.Enabled)
    {
        return true;
    }
    
    return false;
}

static breakpoint
BreakpointCreate(size_t Address)
{
    breakpoint BP = {};
    
    BP.Address = Address;
        
    return BP;
}

static breakpoint
BreakpointCreateAttachSourceLine(size_t Address)
{
    breakpoint BP = BreakpointCreate(Address);
    
    di_src_line *Line = DwarfFindLineByAddress(Address);
    BP.SourceLine = Line ? Line->LineNum : 0;

    return BP;
}

static void
BreakpointEnable(breakpoint *BP)
{
    BP->State.Enabled = true;
    BP->SavedOpCodes = ptrace(PTRACE_PEEKDATA, Debugee.PID, BP->Address, 0x0);
    
    u64 TrapInterupt = 0xcc; // int 3
    u64 OpCodesInt3 = (BP->SavedOpCodes & ~0xff) | TrapInterupt;
    ptrace(PTRACE_POKEDATA, Debugee.PID, BP->Address, OpCodesInt3);
}

static void
BreakpointDisable(breakpoint *BP)
{
    BP->State.Enabled = false;
    ptrace(PTRACE_POKEDATA, Debugee.PID, BP->Address, BP->SavedOpCodes);
}

static void
BreakpointPushAtSourceLine(di_src_file *Src, u32 LineNum, breakpoint *BPs, u32 *Count)
{
    u32 SrcFileIndex = Src - DI->SourceFiles;
    di_src_line *Line = DwarfFindLineByNumber(LineNum, SrcFileIndex);
    
    if(Line)
    {
        bool NoBreakpointAtLine = BreakpointFind(Line->Address) == 0;
        if(NoBreakpointAtLine)
        {
            breakpoint BP = BreakpointCreate(Line->Address);
            BP.SourceLine = LineNum;
            BP.FileIndex = Src - DI->SourceFiles;
            BreakpointEnable(&BP);
            BPs[*Count] = BP;
            *Count += 1;
        }
    }
}

static bool
BreakAtFunctionName(char *Name)
{
    bool Result = false;

    for(u32 I = 0; I < DI->FunctionsCount; I++)
    {
        di_function *Func = &DI->Functions[I];
        if(StringMatches(Name, Func->Name))
        {
            breakpoint BP = BreakpointCreate(Func->FuncLexScope.LowPC);
            BreakpointEnable(&BP);
            Breakpoints[BreakpointCount++] = BP;
            Result = true;
        }
    }

    return Result;
}

static void
BreakAtMain()
{
    size_t EntryPointAddress = DwarfFindEntryPointAddress();
    LOG_FLOW("entrypoint address is %lx\n", EntryPointAddress);
    assert(EntryPointAddress);

#if CLEAR_BREAKPOINTS
    breakpoint BP = BreakpointCreate(EntryPointAddress);
    BreakpointEnable(&BP);
    Breakpoints[BreakpointCount++] = BP;
#else
    breakpoint *BP = BreakpointFind(EntryPointAddress);
    if(!BP)
    {
        LOG_FLOW("Breakpoint is set\n");
        breakpoint BP = BreakpointCreate(EntryPointAddress);
        BreakpointEnable(&BP);
        Breakpoints[BreakpointCount++] = BP;
    }
#endif
}

static bool
BreakAtAddress(size_t Address)
{
    bool Result = false;
    
    breakpoint BP = BreakpointCreate(Address);
    BreakpointEnable(&BP);
    Breakpoints[BreakpointCount++] = BP;
    Result = true;

    return Result;
}

static bool
BreakAtAddress(char *AddressStr)
{
    bool Result = false;

    u64 Address = 0;

    if(StringHasChar(Gui->BreakAddress, 'x'))
    {
        Address = StringHexToInt(AddressStr);
    }
    else
    {
        Address = atol(AddressStr);
    }

    Result = true;
    breakpoint BP = BreakpointCreate(Address);
    BreakpointEnable(&BP);
    Breakpoints[BreakpointCount++] = BP;

    return Result;
}

static void
DebugeeStepInstruction()
{
    i32 PID = Debugee.PID;
    breakpoint *BP = BreakpointFind(DebugeeGetProgramCounter());
    if(BP && BreakpointEnabled(BP) && !BP->State.ExectuedSavedOpCode) { BreakpointDisable(BP); }
    
    ptrace(PTRACE_SINGLESTEP, PID, 0x0, 0x0);
    DebugeeWaitForSignal();
    
    if(BP && !BreakpointEnabled(BP) && !BP->State.ExectuedSavedOpCode) { BreakpointEnable(BP); }
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
BreakAtCurcialInstrsInRange(address_range Range, bool BreakCalls, breakpoint *Breakpoints, u32 *BreakpointsCount)
{
    bool AddressWithoutBreakpoint = !BreakpointFind(Range.End, Breakpoints, (*BreakpointsCount));
    if(AddressWithoutBreakpoint)
    {
        breakpoint BP = BreakpointCreate(Range.End);
        BreakpointEnable(&BP);
        Breakpoints[(*BreakpointsCount)++] = BP;
    }

    cs_insn *Instruction = 0x0;
    for(size_t CurrentAddress = Range.Start; CurrentAddress < Range.End;)
    {
        u8 InstrInMemory[16] = {};
        DebugeePeekMemoryArray(CurrentAddress, Range.End, InstrInMemory, sizeof(InstrInMemory));

        {
            breakpoint *BP = 0x0; ;
            if((BP = BreakpointFind(CurrentAddress)) && BreakpointEnabled(BP))
            {
                InstrInMemory[0] = (u8)(BP->SavedOpCodes & 0xff);
            }
        }
        
        int Count = cs_disasm(DisAsmHandle, InstrInMemory, sizeof(InstrInMemory),
                              CurrentAddress, 1, &Instruction);
        if(Count == 0) { break; }
        
        CurrentAddress += Instruction->size;
        inst_type Type = AsmInstructionGetType(Instruction);
        
        if((Type & INST_TYPE_CALL) && BreakCalls)
        {
            LOG_FLOW("Breaking because of call\n");
            
            // NOTE(mateusz): Should always be one, otherwise not a valid opcode
            assert(Instruction->detail->x86.op_count == 1);
            
            size_t CallAddress = 0x0;
            auto Operand = &Instruction->detail->x86.operands[0];
            if(Operand->type == X86_OP_IMM)
            {
                CallAddress = Operand->imm;
            }
            else if(Operand->type == X86_OP_REG)
            {
                u32 ABINumber = CapstoneRegisterToABINumber(Operand->reg);
                CallAddress = RegisterGetByABINumber(Debugee.Regs, ABINumber);
            }
            else
            {
                assert(false && "A call instruction that is not imm and not a reg.");
            }
            
            bool AddressInAnyCompileUnit = DwarfFindCompileUnitByAddress(CallAddress) != 0x0;
            if(AddressInAnyCompileUnit && !BreakpointFind(CallAddress, Breakpoints, (*BreakpointsCount)))
            {
                breakpoint BP = BreakpointCreate(CallAddress);
                BreakpointEnable(&BP);
                Breakpoints[(*BreakpointsCount)++] = BP;
            }
        }
        
        if(Type & INST_TYPE_RET)
        {
            size_t ReturnAddress = DebugeeGetReturnAddress(DebugeeGetProgramCounter());

            bool AddressInAnyCompileUnit = DwarfFindCompileUnitByAddress(ReturnAddress) != 0x0;
            if(AddressInAnyCompileUnit && !BreakpointFind(ReturnAddress, Breakpoints, (*BreakpointsCount)))
            {
                breakpoint BP = BreakpointCreate(ReturnAddress);
                BreakpointEnable(&BP);
                Breakpoints[(*BreakpointsCount)++] = BP;
            }
        }

        if((Type & INST_TYPE_RELATIVE_BRANCH) && (Type & INST_TYPE_JUMP))
        {
            
            // NOTE(mateusz): Should always be one, otherwise not a valid opcode
            assert(Instruction->detail->x86.op_count == 1);
            
            size_t JumpAddress = Instruction->detail->x86.operands[0].imm;
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
            
            LOG_FLOW("OperandAddress = %lX, Range.Start = %lX, Range.End = %lX\n", JumpAddress, Range.Start, Range.End);
            
            bool AddressWithoutBreakpoint = !BreakpointFind(JumpAddress, Breakpoints, (*BreakpointsCount));
            if(AddressWithoutBreakpoint)
            {
                bool Between = AddressBetween(JumpAddress, Range.Start, Range.End);
                bool DiffrentLine = DwarfIsAddressInDifferentSourceLine(JumpAddress);
                if(!Between && DiffrentLine)
                {
                    LOG_FLOW("Breaking rel branch: %lX\n", JumpAddress);

                    breakpoint BP = BreakpointCreate(JumpAddress);
                    BreakpointEnable(&BP);
                    Breakpoints[(*BreakpointsCount)++] = BP;
                }
                else 
                {
                    address_range JumpToNextLine = DwarfGetAddressRangeUntilNextLine(JumpAddress);
                    if(JumpToNextLine.Start != Range.Start && JumpToNextLine.End != Range.End)
                    {
                        BreakAtCurcialInstrsInRange(JumpToNextLine, false, Breakpoints, BreakpointsCount);
                    }
                }
            }
        }
        
        if(Instruction) { cs_free(Instruction, 1); }
    }
}

static void
DebugeeToNextLine(bool StepIntoFunctions)
{
    address_range Range = DwarfGetAddressRangeUntilNextLine(DebugeeGetProgramCounter());
    LOG_FLOW("Regs.RIP = %lX, Range.Start = %lX, Range.End = %lX\n", DebugeeGetProgramCounter(), Range.Start, Range.End);

    BreakAtCurcialInstrsInRange(Range, StepIntoFunctions, TempBreakpoints, &TempBreakpointsCount);
    
    DebugeeContinueProgram();
    
    LOG_FLOW("TempBreakpointsCount = %d\n", TempBreakpointsCount);
    for(u32 I = 0; I < TempBreakpointsCount; I++)
    {
        LOG_FLOW("Breakpoint[%d] at %lX\n", I, TempBreakpoints[I].Address);
        BreakpointDisable(&TempBreakpoints[I]);
    }

    memset(TempBreakpoints, 0, sizeof(TempBreakpoints[0]) * TempBreakpointsCount);
    TempBreakpointsCount = 0;
    
    Debugee.Flags.Steped = true;
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

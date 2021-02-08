#ifdef DEBUG
#define LOG_FLOW(fmt, ...) if(Debuger.Log.FlowLogs) { printf(fmt, ##__VA_ARGS__); }
#else
#define LOG_FLOW(...) do { } while (0)
#endif

static bool
AddressInDiffrentLine(size_t Address)
{
    di_src_line *Current = LineTableFindByAddress(GetProgramCounter());
    di_src_line *Diff = LineTableFindByAddress(Address);
    assert(Current);
    assert(Diff);

    LOG_FLOW("LineNum: Current = %u, Diff = %u / Address: Current = %lx, Diff = %lx\n", Current->LineNum, Diff->LineNum, Current->Address, Diff->Address);

    bool SameLineDiffFiles = (Current->LineNum == Diff->LineNum) && (Current->SrcFileIndex != Diff->SrcFileIndex);
    bool SameFileDiffLines = (Current->LineNum != Diff->LineNum) && (Current->Address != Diff->Address);
    if(SameLineDiffFiles || SameFileDiffLines)
    {
        assert(Current != Diff);
        return true;
    }
        
    return false;
}

static void
WaitForSignal(i32 DebugeePID)
{
    i32 WaitStatus;
    i32 Options = 0;
    waitpid(DebugeePID, &WaitStatus, Options);
    
    if(WIFEXITED(WaitStatus))
    {
        GuiSetStatusText("Program finished it's execution");
        Debuger.Flags &= ~DEBUGEE_FLAG_RUNNING;
        DeallocDebugInfo();
    }
    
    siginfo_t SigInfo;
    ptrace(PTRACE_GETSIGINFO, DebugeePID, nullptr, &SigInfo);
    
    if(SigInfo.si_signo == SIGTRAP)
    {
        switch (SigInfo.si_code)
        {
            case SI_KERNEL:
            case TRAP_BRKPT:
            {
                Debuger.Regs = PeekRegisters(DebugeePID);
                Debuger.Regs.RIP -= 1;
                SetRegisters(Debuger.Regs, DebugeePID);
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
        DeallocDebugInfo();
    }
    else if(SigInfo.si_signo == SIGABRT)
    {
        DebugeeKill();
        GuiSetStatusText("Program aborted");
        DeallocDebugInfo();
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
    
    di_src_line *Line = LineTableFindByAddress(Address);
    BP.SourceLine = Line ? Line->LineNum : 0;

    return BP;
}

static void
BreakpointEnable(breakpoint *BP)
{
    BP->State.Enabled = true;
    BP->SavedOpCodes = ptrace(PTRACE_PEEKDATA, Debuger.DebugeePID, BP->Address, 0x0);
    
    u64 TrapInterupt = 0xcc; // int 3
    u64 OpCodesInt3 = (BP->SavedOpCodes & ~0xff) | TrapInterupt;
    ptrace(PTRACE_POKEDATA, Debuger.DebugeePID, BP->Address, OpCodesInt3);
}

static void
BreakpointDisable(breakpoint *BP)
{
    BP->State.Enabled = false;
    ptrace(PTRACE_POKEDATA, Debuger.DebugeePID, BP->Address, BP->SavedOpCodes);
}

static void
BreakpointPushAtSourceLine(di_src_file *Src, u32 LineNum, breakpoint *BPs, u32 *Count)
{
    u32 SrcFileIndex = Src - DI->SourceFiles;
    di_src_line *Line = LineFindByNumber(LineNum, SrcFileIndex);
    
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

    for(u32 I = 0; I < DI->FuctionsCount; I++)
    {
        di_function *Func = &DI->Functions[I];
        if(StringsMatch(Name, Func->Name))
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
    size_t EntryPointAddress = FindEntryPointAddress();
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
BreakAtAddress(char *AddressStr)
{
    bool Result = false;

    u64 Address = 0;

    if(CharInString(Gui->BreakAddress, 'x'))
    {
        Address = HexStringToInt(AddressStr);
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
StepInstruction(i32 DebugeePID)
{
    breakpoint *BP = BreakpointFind(GetProgramCounter());
    if(BP && BreakpointEnabled(BP) && !BP->State.ExectuedSavedOpCode) { BreakpointDisable(BP); }
    
    ptrace(PTRACE_SINGLESTEP, DebugeePID, 0x0, 0x0);
    WaitForSignal(DebugeePID);
    
    if(BP && !BreakpointEnabled(BP) && !BP->State.ExectuedSavedOpCode) { BreakpointEnable(BP); }
    if(BP) { BP->State.ExectuedSavedOpCode = !BP->State.ExectuedSavedOpCode; }
    
    Debuger.Regs = PeekRegisters(DebugeePID);

    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
}

static void
NextInstruction(i32 DebugeePID)
{
    (void)DebugeePID;
    LOG_FLOW("Unimplemented method!");
    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
}

static void
StepLine(i32 DebugeePID)
{
    di_src_line *LTEntry = LineTableFindByAddress(GetProgramCounter());
    assert(LTEntry);
    
    while(true)
    {
        StepInstruction(DebugeePID);
        
        di_src_line *CurrentLTE = LineTableFindByAddress(GetProgramCounter());
        if(CurrentLTE && LTEntry->LineNum != CurrentLTE->LineNum)
        {
            break;
        }
    }
}

static void
ContinueProgram(i32 DebugeePID)
{
    if(BreakpointCount > 0)
    {
        size_t OldPC = GetProgramCounter();
        StepInstruction(DebugeePID);
        
        breakpoint *BP = BreakpointFind(OldPC);
        if(BreakpointEnabled(BP))
        {
            BP->State.ExectuedSavedOpCode = false;
        }
    }
    
    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
    
    ptrace(PTRACE_CONT, DebugeePID, 0x0, 0x0);
    WaitForSignal(DebugeePID);
}

static void
BreakAtCurcialInstrsInRange(address_range Range, bool BreakCalls, i32 DebugeePID, breakpoint *Breakpoints, u32 *BreakpointsCount)
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
        PeekDebugeeMemoryArray(CurrentAddress, Range.End,
                               DebugeePID, InstrInMemory, sizeof(InstrInMemory));

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
        inst_type Type = GetInstructionType(Instruction);
        
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
                CallAddress = GetRegisterByABINumber(Debuger.Regs, ABINumber);
            }
            else
            {
                assert(false && "A call instruction that is not imm and not a reg.");
            }
            
            bool AddressInAnyCompileUnit = FindCompileUnitConfiningAddress(CallAddress) != 0x0;
            if(AddressInAnyCompileUnit && !BreakpointFind(CallAddress, Breakpoints, (*BreakpointsCount)))
            {
                breakpoint BP = BreakpointCreate(CallAddress);
                BreakpointEnable(&BP);
                Breakpoints[(*BreakpointsCount)++] = BP;
            }
        }
        
        if(Type & INST_TYPE_RET)
        {
            size_t ReturnAddress = PeekDebugeeMemory(Debuger.Regs.RBP + 8, DebugeePID);

            bool AddressInAnyCompileUnit = FindCompileUnitConfiningAddress(ReturnAddress) != 0x0;
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
                JumpAddress = GetRegisterByABINumber(Debuger.Regs, ABINumber);
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
                bool DiffrentLine = AddressInDiffrentLine(JumpAddress);
                if(!Between && DiffrentLine)
                {
                    LOG_FLOW("Breaking rel branch: %lX\n", JumpAddress);

                    breakpoint BP = BreakpointCreate(JumpAddress);
                    BreakpointEnable(&BP);
                    Breakpoints[(*BreakpointsCount)++] = BP;
                }
                else 
                {
                    address_range JumpToNextLine = AddressRangeCurrentAndNextLine(JumpAddress);
                    if(JumpToNextLine.Start != Range.Start && JumpToNextLine.End != Range.End)
                    {
                        BreakAtCurcialInstrsInRange(JumpToNextLine, false, DebugeePID,
                                                    Breakpoints, BreakpointsCount);
                    }
                }
            }
        }
        
        if(Instruction) { cs_free(Instruction, 1); }
    }
}

static void
ToNextLine(i32 DebugeePID, bool StepIntoFunctions)
{
    address_range Range = AddressRangeCurrentAndNextLine(GetProgramCounter());
    
    LOG_FLOW("Regs.RIP = %lX, Range.Start = %lX, Range.End = %lX\n", GetProgramCounter(), Range.Start, Range.End);
    
    breakpoint TempBreakpoints[32] = {};
    u32 TempBreakpointsCount = 0;
    
    BreakAtCurcialInstrsInRange(Range, StepIntoFunctions, DebugeePID, TempBreakpoints, &TempBreakpointsCount);
    
    ContinueProgram(DebugeePID);
    
    LOG_FLOW("TempBreakpointsCount = %d\n", TempBreakpointsCount);
    for(u32 I = 0; I < TempBreakpointsCount; I++)
    {
        LOG_FLOW("Breakpoint[%d] at %lX\n", I, TempBreakpoints[I].Address);
        BreakpointDisable(&TempBreakpoints[I]);
    }
    
    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
}

static void
StepOutOfFunction(i32 DebugeePID)
{
    di_function *Func = FindFunctionConfiningAddress(GetProgramCounter());

    ToNextLine(DebugeePID, false);
    UpdateInfo();

    size_t PC = GetProgramCounter();
    if(AddressInFunction(Func, PC))
    {
        size_t ReturnAddress = GetReturnAddress(GetProgramCounter());
        bool OwnBreakpoint = false;
        breakpoint BP = {};

        if(!BreakpointFind(ReturnAddress))
        {
            BP = BreakpointCreate(ReturnAddress);
            BreakpointEnable(&BP);
            OwnBreakpoint = true;
        }
    
        ContinueProgram(DebugeePID);
        if(OwnBreakpoint)
        {
            BreakpointDisable(&BP);
        }
    }
    
    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
}

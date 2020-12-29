static bool
AddressInDiffrentLine(size_t Address)
{
    di_src_line *Current = LineTableFindByAddress(Regs.rip);
    di_src_line *Diff = LineTableFindByAddress(Address);
    assert(Current);
    assert(Diff);

    printf("LineNum: Current = %u, Diff = %u / Address: Current = %lx, Diff = %lx\n", Current->LineNum, Diff->LineNum, Current->Address, Diff->Address);

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
        printf("Program finished it's execution\n");
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
                Regs = PeekRegisters(DebugeePID);
                Regs.rip -= 1;
                SetRegisters(Regs, DebugeePID);
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
        printf("Program seg faulted\n");
    }
    else
    {
        printf("Unhandled signal = [%s]", strsignal(SigInfo.si_signo));
    }
}

static breakpoint *
BreakpointFind(u64 Address, i32 DebugeePID, breakpoint *BPs, u32 Count)
{
    for(u32 I = 0; I < Count; I++)
    {
        breakpoint *BP = &BPs[I];
        if(BP->Address == Address && BP->DebugeePID == DebugeePID)
        {
            return BP;
        }
    }
    
    return 0x0;
}

static breakpoint *
BreakpointFind(u64 Address, i32 DebugeePID)
{
    breakpoint *Result = 0x0;
    
    Result = BreakpointFind(Address, DebugeePID, Breakpoints, BreakpointCount);
    
    return Result;
}

static bool
BreakpointEnabled(breakpoint *BP)
{
    if(BP && BP->Enabled)
    {
        return true;
    }
    
    return false;
}

static breakpoint
BreakpointCreate(u64 Address, i32 DebugeePID)
{
    breakpoint BP = {};
    //u64 OpCodes = ptrace(PTRACE_PEEKDATA, DebugeePID, Address, 0x0);
    //breakpoint *BP = &Breakpoints[BreakpointCount++];
    //assert(BreakpointCount != MAX_BREAKPOINT_COUNT);
    
    BP.Address = Address;
    BP.DebugeePID = DebugeePID;
    
    return BP;
}

static void
BreakpointEnable(breakpoint *BP)
{
    BP->Enabled = true;
    // NOTE(mateusz): @Speed: The memory is only really volatile in instruction land
    // if someone has a self-modifying exectuable. So if you don't want to support that
    // just store the opcodes at Instruction Pointer in the struct of breakpoint, it will 
    // speed this up a bit, I don't know how much of a problem this will be.
    u64 OpCodes = ptrace(PTRACE_PEEKDATA, BP->DebugeePID, BP->Address, 0x0);
    BP->SavedOpCode = OpCodes & 0xff;
    u64 TrapInterupt = 0xcc; // int 3
    u64 OpCodesInt3 = (OpCodes & ~0xff) | TrapInterupt;
    ptrace(PTRACE_POKEDATA, BP->DebugeePID, BP->Address, OpCodesInt3);
}

static void
BreakpointDisable(breakpoint *BP)
{
    BP->Enabled = false;
    u64 OpCodes = ptrace(PTRACE_PEEKDATA, BP->DebugeePID, BP->Address, 0x0);
    u64 RestoredOpCodes = (OpCodes & ~0xff) | BP->SavedOpCode;
    ptrace(PTRACE_POKEDATA, BP->DebugeePID, BP->Address, RestoredOpCodes);
}

static void
BreakpointPushAtSourceLine(di_src_file *Src, u32 LineNum, breakpoint *BPs, u32 *Count)
{
    u32 SrcFileIndex = Src - DI->SourceFiles;
    di_src_line *Line = LineFindByNumber(LineNum, SrcFileIndex);
    
    if(Line)
    {
        bool NoBreakpointAtLine = BreakpointFind(Line->Address, Debuger.DebugeePID) == 0;
        if(NoBreakpointAtLine)
        {
            breakpoint BP = BreakpointCreate(Line->Address, Debuger.DebugeePID);
            BreakpointEnable(&BP);
            BPs[*Count] = BP;
            *Count += 1;
        }
    }
}

static void
StepInstruction(i32 DebugeePID)
{
    breakpoint *BP = BreakpointFind(Regs.rip, DebugeePID);
    if(BP && BreakpointEnabled(BP) && !BP->ExectuedSavedOpCode) { BreakpointDisable(BP); }
    
    ptrace(PTRACE_SINGLESTEP, DebugeePID, 0x0, 0x0);
    WaitForSignal(DebugeePID);
    
    if(BP && !BreakpointEnabled(BP) && !BP->ExectuedSavedOpCode) { BreakpointEnable(BP); }
    if(BP) { BP->ExectuedSavedOpCode = !BP->ExectuedSavedOpCode; }
    
    Regs = PeekRegisters(DebugeePID);
}

static void
StepLine(i32 DebugeePID)
{
    di_src_line *LTEntry = LineTableFindByAddress(Regs.rip);
    assert(LTEntry);
    
    while(true)
    {
        StepInstruction(DebugeePID);
        
        di_src_line *CurrentLTE = LineTableFindByAddress(Regs.rip);
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
        size_t OldPC = Regs.rip;
        StepInstruction(DebugeePID);
        
        breakpoint *BP = BreakpointFind(OldPC, DebugeePID);
        if(BreakpointEnabled(BP))
        {
            BP->ExectuedSavedOpCode = false;
        }
    }
    
    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
    
    ptrace(PTRACE_CONT, DebugeePID, 0x0, 0x0);
    WaitForSignal(DebugeePID);
}

static void
BreakAtCurcialInstrsInRange(address_range Range, bool BreakCalls, i32 DebugeePID, breakpoint *Breakpoints, u32 *BreakpointsCount)
{
    breakpoint BP = BreakpointCreate(Range.End, DebugeePID);
    BreakpointEnable(&BP);
    Breakpoints[(*BreakpointsCount)++] = BP;

    cs_insn *Instruction = 0x0;
    for(size_t CurrentAddress = Range.Start; CurrentAddress < Range.End;)
    {
        u8 InstrInMemory[16] = {};
        PeekDebugeeMemoryArray(CurrentAddress, Range.End,
                               DebugeePID, InstrInMemory, sizeof(InstrInMemory));

        {
            breakpoint *BP = 0x0; ;
            if((BP = BreakpointFind(CurrentAddress, DebugeePID)) && BreakpointEnabled(BP))
            {
                InstrInMemory[0] = BP->SavedOpCode;
            }
        }
        
        int Count = cs_disasm(DisAsmHandle, InstrInMemory, sizeof(InstrInMemory),
                              CurrentAddress, 1, &Instruction);
        if(Count == 0) { break; }
        
        CurrentAddress += Instruction->size;
        inst_type Type = GetInstructionType(Instruction);
        
        if((Type & INST_TYPE_CALL) && BreakCalls)
        {
            // NOTE(mateusz): Should always be one, otherwise not a valid opcode
            assert(Instruction->detail->x86.op_count == 1);
            // TODO(mateusz): This is here just for me to remeber to implement jumps
            // that are not specified by fixed memory locations but rather register
            // values i.e. jump tables
            assert(Instruction->detail->x86.operands[0].imm > 0x100);
            
            //printf("Breaking because of call\n");
            size_t CallAddress = Instruction->detail->x86.operands[0].imm;
            
            if(AddressInAnyCompileUnit(CallAddress))
            {
                breakpoint BP = BreakpointCreate(CallAddress, DebugeePID);
                BreakpointEnable(&BP);
                Breakpoints[(*BreakpointsCount)++] = BP;
            }
        }
        
        if(Type & INST_TYPE_RET)
        {
            size_t ReturnAddress = PeekDebugeeMemory(Regs.rbp + 8, DebugeePID);

            if(AddressInAnyCompileUnit(ReturnAddress))
            {
                breakpoint BP = BreakpointCreate(ReturnAddress, DebugeePID);
                BreakpointEnable(&BP);
                Breakpoints[(*BreakpointsCount)++] = BP;
            }
        }

        if((Type & INST_TYPE_RELATIVE_BRANCH) && (Type & INST_TYPE_JUMP))
        {
            // NOTE(mateusz): Should always be one, otherwise not a valid opcode
            assert(Instruction->detail->x86.op_count == 1);
            // TODO(mateusz): This is here just for me to remeber to implement jumps
            // that are not specified by fixed memory locations but rather register
            // values i.e. jump tables
            assert(Instruction->detail->x86.operands[0].imm > 0x100);
            
            size_t JumpAddress = Instruction->detail->x86.operands[0].imm;
            //printf("OperandAddress = %lX, Range.Start = %lX, Range.End = %lX\n", JumpAddress, Range.Start, Range.End);
            
            bool AddressWithoutBreakpoint = !BreakpointFind(JumpAddress, DebugeePID,
                                                            Breakpoints, (*BreakpointsCount));
            if(AddressWithoutBreakpoint)
            {
                bool Between = AddressBetween(JumpAddress, Range.Start, Range.End);
                bool DiffrentLine = AddressInDiffrentLine(JumpAddress);
                if(!Between && DiffrentLine)
                {
                    //printf("Breaking rel branch: %lX\n", JumpAddress);

                    breakpoint BP = BreakpointCreate(JumpAddress, DebugeePID);
                    BreakpointEnable(&BP);
                    Breakpoints[(*BreakpointsCount)++] = BP;
                }
                else 
                {
                    address_range JumpToNextLine = AddressRangeCurrentAndNextLine(JumpAddress);

                    BreakAtCurcialInstrsInRange(JumpToNextLine, false, DebugeePID,
                                                Breakpoints, BreakpointsCount);
                }
            }
        }
        
        if(Instruction) { cs_free(Instruction, 1); }
    }
}

static void
ToNextLine(i32 DebugeePID, bool StepIntoFunctions)
{
    address_range Range = AddressRangeCurrentAndNextLine(Regs.rip);
    
//    printf("Regs.rip = %llX, Range.Start = %lX, Range.End = %lX\n", Regs.rip, Range.Start, Range.End);
    
    breakpoint TempBreakpoints[8] = {};
    u32 TempBreakpointsCount = 0;
    
    BreakAtCurcialInstrsInRange(Range, StepIntoFunctions, DebugeePID, TempBreakpoints, &TempBreakpointsCount);
    
    ContinueProgram(DebugeePID);
    
//    printf("TempBreakpointsCount = %d\n", TempBreakpointsCount);
    for(u32 I = 0; I < TempBreakpointsCount; I++)
    {
//        printf("Breakpoint[%d] at %lX\n", I, TempBreakpoints[I].Address);
        BreakpointDisable(&TempBreakpoints[I]);
    }
    
    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
    
}

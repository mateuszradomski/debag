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
        printf("We are true\n");
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
ToNextLine(i32 DebugeePID, bool StepIntoFunctions)
{
    address_range Range = AddressRangeCurrentAndNextLine();
    
    printf("Regs.rip = %llX, Range.Start = %lX, Range.End = %lX\n", Regs.rip, Range.Start, Range.End);
    
    breakpoint TempBreakpoints[8] = {};
    u32 TempBreakpointsCount = 0;
    
    breakpoint BP = BreakpointCreate(Range.End, DebugeePID);
    BreakpointEnable(&BP);
    TempBreakpoints[TempBreakpointsCount++] = BP;
    
    cs_insn *Instruction = 0x0;
    for(size_t CurrentAddress = Range.Start; CurrentAddress < Range.End;)
    {
        size_t MachineWord = PeekDebugeeMemory(CurrentAddress, DebugeePID);
        
        breakpoint *BP = BreakpointFind(CurrentAddress, DebugeePID);
        if(BreakpointEnabled(BP))
        {
            MachineWord = (MachineWord & ~0xff) | BP->SavedOpCode;
        }
        
        int Count = cs_disasm(DisAsmHandle, (const u8 *)&MachineWord,
                              sizeof(MachineWord), CurrentAddress, 1, &Instruction);
        if(Count == 0) { break; }
        
        CurrentAddress += Instruction->size;
        
        inst_type Type = GetInstructionType(Instruction);
        
        if((Type & INST_TYPE_CALL) && StepIntoFunctions)
        {
            // NOTE(mateusz): Should always be one, otherwise not a valid opcode
            assert(Instruction->detail->x86.op_count == 1);
            // TODO(mateusz): This is here just for me to remeber to implement jumps
            // that are not specified by fixed memory locations but rather register
            // values i.e. jump tables
            assert(Instruction->detail->x86.operands[0].imm > 0x100);
            
            //printf("Breaking because of call\n");
            size_t CallAddress = Instruction->detail->x86.operands[0].imm;
            
            for(u32 I = 0; I < DI->CompileUnitsCount; I++)
            {
                di_compile_unit *CU = &DI->CompileUnits[I];
                for(u32 RI = 0; RI < CU->RangesCount; RI++)
                {
                    if(AddressBetween(CallAddress, CU->RangesLowPCs[RI], CU->RangesHighPCs[RI]))
                    {
                        breakpoint BP = BreakpointCreate(CallAddress, DebugeePID);
                        BreakpointEnable(&BP);
                        TempBreakpoints[TempBreakpointsCount++] = BP;
                        goto END_TYPE_CALL;
                    }
                }
            }
        }
        
        END_TYPE_CALL:;
        
        if(Type & INST_TYPE_RET)
        {
            size_t ReturnAddress = PeekDebugeeMemory(Regs.rbp + 8, DebugeePID);
            
            for(u32 I = 0; I < DI->CompileUnitsCount; I++)
            {
                di_compile_unit *CU = &DI->CompileUnits[I];
                for(u32 RI = 0; RI < CU->RangesCount; RI++)
                {
                    if(AddressBetween(ReturnAddress, CU->RangesLowPCs[RI], CU->RangesHighPCs[RI]))
                    {
                        breakpoint BP = BreakpointCreate(ReturnAddress, DebugeePID);
                        BreakpointEnable(&BP);
                        TempBreakpoints[TempBreakpointsCount++] = BP;
                        
                        //printf("Breaking because of return: %lX\n", ReturnAddress);
                        goto END_TYPE_RET;
                    }
                }
            }
        }
        
        END_TYPE_RET:;
        
        if((Type & INST_TYPE_RELATIVE_BRANCH) && (Type & INST_TYPE_JUMP))
        {
            // NOTE(mateusz): Should always be one, otherwise not a valid opcode
            assert(Instruction->detail->x86.op_count == 1);
            // TODO(mateusz): This is here just for me to remeber to implement jumps
            // that are not specified by fixed memory locations but rather register
            // values i.e. jump tables
            assert(Instruction->detail->x86.operands[0].imm > 0x100);
            
            size_t JumpAddress = Instruction->detail->x86.operands[0].imm;
            printf("OperandAddress = %lX, Range.Start = %lX, Range.End = %lX\n", JumpAddress, Range.Start, Range.End);
            
            bool Between = AddressBetween(JumpAddress, Range.Start, Range.End);
            bool DiffrentLine = AddressInDiffrentLine(JumpAddress);
            if(!Between && DiffrentLine)
            {
                printf("Breaking rel branch: %lX\n", JumpAddress);
                
                breakpoint BP = BreakpointCreate(JumpAddress, DebugeePID);
                BreakpointEnable(&BP);
                TempBreakpoints[TempBreakpointsCount++] = BP;
            }
            else 
            {
                size_t CurrentAddress = JumpAddress;
                while(true)
                {
                    size_t DeepOpcodes = PeekDebugeeMemory(CurrentAddress, Debuger.DebugeePID);
                    
                    breakpoint *BP = BreakpointFind(CurrentAddress, DebugeePID);
                    if(BreakpointEnabled(BP))
                    {
                        DeepOpcodes = (DeepOpcodes & ~0xff) | BP->SavedOpCode;
                    }
                    
                    if(Instruction) { cs_free(Instruction, 1); }
                    i32 Count = cs_disasm(DisAsmHandle, (const u8 *)&DeepOpcodes, 
                                          sizeof(DeepOpcodes), CurrentAddress, 1, &Instruction);
                    if(Count == 0) { break; }
                    CurrentAddress += Instruction->size;
                    
                    inst_type DeepType = GetInstructionType(Instruction);
                    if((DeepType & INST_TYPE_RELATIVE_BRANCH) && (DeepType & INST_TYPE_JUMP))
                    {
                        assert(Instruction->detail->x86.op_count == 1);
                        assert(Instruction->detail->x86.operands[0].imm > 0x100);
                        
                        size_t OperandAddress = Instruction->detail->x86.operands[0].imm;
                        if(!BreakpointFind(OperandAddress, DebugeePID, TempBreakpoints, TempBreakpointsCount))
                        {
                            printf("OperandAddress = %lX, Range.Start = %lX, Range.End = %lX\n", OperandAddress, Range.Start, Range.End);
                            
                            printf("Break condition branch in jump instrs: %lX\n", OperandAddress);
                            if(OperandAddress != Range.Start)
                            {
                                breakpoint BP = BreakpointCreate(OperandAddress, DebugeePID);
                                BreakpointEnable(&BP);
                                TempBreakpoints[TempBreakpointsCount++] = BP;
                            }
                        }
                    }
                    
                    if(Type & INST_TYPE_RET)
                    {
                        size_t ReturnAddress = PeekDebugeeMemory(Regs.rbp + 8, DebugeePID);
                        
                        for(u32 I = 0; I < DI->CompileUnitsCount; I++)
                        {
                            di_compile_unit *CU = &DI->CompileUnits[I];
                            for(u32 RI = 0; RI < CU->RangesCount; RI++)
                            {
                                if(AddressBetween(ReturnAddress, CU->RangesLowPCs[RI], CU->RangesHighPCs[RI]))
                                {
                                    breakpoint BP = BreakpointCreate(ReturnAddress, DebugeePID);
                                    BreakpointEnable(&BP);
                                    TempBreakpoints[TempBreakpointsCount++] = BP;
                                    
                                    //printf("Breaking because of return: %lX\n", ReturnAddress);
                                    goto END_TYPE_RET_DEEP;
                                }
                            }
                        }
                    }
                    
                    END_TYPE_RET_DEEP:;
                    
                    // TODO(mateusz): This isn't that safe I guess
                    // It's created upon a feeling I have of programs, nothing
                    // doc/spec based
                    if(Instruction->id == X86_INS_JMP || Instruction->id == X86_INS_JB)
                    {
                        if(Instruction) { cs_free(Instruction, 1); }
                        i32 Count = cs_disasm(DisAsmHandle, (const u8 *)&DeepOpcodes, 
                                              sizeof(DeepOpcodes), CurrentAddress, 1, &Instruction);
                        if(Count == 0) { break; }
                        CurrentAddress += Instruction->size;

                        breakpoint BP = BreakpointCreate(CurrentAddress, DebugeePID);
                        BreakpointEnable(&BP);
                        TempBreakpoints[TempBreakpointsCount++] = BP;

                        break;
                    }
                }
            }
        }
        
        if(Instruction) { cs_free(Instruction, 1); }
    }
    
    ContinueProgram(DebugeePID);
    
    printf("TempBreakpointsCount = %d\n", TempBreakpointsCount);
    for(u32 I = 0; I < TempBreakpointsCount; I++)
    {
        printf("Breakpoint[%d] at %lX\n", I, TempBreakpoints[I].Address);
        BreakpointDisable(&TempBreakpoints[I]);
    }
    
    Debuger.Flags |= DEBUGEE_FLAG_STEPED;
    
}

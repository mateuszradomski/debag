#ifdef DEBUG
#define LOG_FLOW(fmt, ...) if(Debuger.Log.FlowLogs) { printf(fmt, ##__VA_ARGS__); }
#else
#define LOG_FLOW(...) do { } while (0)
#endif

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
    size_t MachineWord = DebugeePeekMemory(&Debugee, BP->Address);

    size_t PokeData = (MachineWord & (~0xff)) | (BP->SavedOpCodes & 0xff);
    
    ptrace(PTRACE_POKEDATA, Debugee.PID, BP->Address, PokeData);
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
        DebugeePeekMemoryArray(&Debugee, CurrentAddress, Range.End, InstrInMemory, sizeof(InstrInMemory));

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
            size_t ReturnAddress = DebugeeGetReturnAddress(&Debugee, DebugeeGetProgramCounter(&Debugee));

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

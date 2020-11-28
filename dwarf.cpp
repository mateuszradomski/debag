static di_src_line *
LineTableFindByAddress(size_t Address)
{
    for(u32 I = 0; I < DISourceLinesCount; I++)
    {
        if(DISourceLines[I].Address == Address)
        {
            return &DISourceLines[I];
        }
        else if(I + 1 < DISourceLinesCount &&
                (DISourceLines[I].Address < Address) &&
                (DISourceLines[I + 1].Address > Address))
        {
            return &DISourceLines[I];
        }
    }
    
    return 0x0;
}

static di_src_line *
LineTableFindByLineNum(u32 LineNum)
{
    for(u32 I = 0; I < DISourceLinesCount; I++)
    {
        if(DISourceLines[I].LineNum == LineNum)
        {
            return &DISourceLines[I];
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

static di_function *
FindFunctionConfiningAddress(size_t Address)
{
    di_function *Result = 0x0;
    
    for(u32 I = 0; I < DIFuctionsCount; I++)
    {
        di_function *Func = &DIFunctions[I];
        if(AddressBetween(Address, Func->DIFuncLexScope.LowPC, Func->DIFuncLexScope.HighPC))
        {
            Result = &DIFunctions[I];
            break;
        }
    }
    
    return Result;
}

static di_base_type *
FindBaseTypeByOffset(size_t BTDIEOffset, type_flags *TFlags)
{
    di_base_type *Type = 0x0;
    
    size_t LookForOffset = BTDIEOffset;
    for(u32 I = 0; I < DITypedefsCount; I++)
    {
        if(DITypedefs[I].DIEOffset == LookForOffset)
        {
            LookForOffset = DITypedefs[I].ActualTypeOffset;
            if(TFlags)
            {
                *TFlags |= TYPE_IS_TYPEDEF;
            }
            goto EndSearch;
        }
    }
    
    for(u32 I = 0; I < DIPointerTypesCount; I++)
    {
        if(DIPointerTypes[I].DIEOffset == LookForOffset)
        {
            LookForOffset = DIPointerTypes[I].ActualTypeOffset;
            if(TFlags)
            {
                *TFlags |= TYPE_IS_POINTER;
            }
            goto EndSearch;
        }
    }
    
    EndSearch:;
    for(u32 I = 0; I < DIBaseTypesCount; I++)
    {
        if(DIBaseTypes[I].DIEOffset == LookForOffset)
        {
            Type = &DIBaseTypes[I];
            if(TFlags)
            {
                *TFlags |= TYPE_IS_BASE;
            }
            break;
        }
    }
    
    return Type;
}


static di_base_type *
FindBaseTypeByOffset(size_t BTDIEOffset)
{
    di_base_type *Type = 0x0;
    
    Type = FindBaseTypeByOffset(BTDIEOffset, 0x0);
    
    return Type;
}

static char *
BaseTypeToFormatStr(di_base_type *Type, type_flags TFlag)
{
    char *Result = "";
    
    if(Type && (TFlag & TYPE_IS_POINTER))
    {
        Result = "%p";
    }
    else if(Type)
    {
        switch(Type->ByteSize)
        {
            case 1:
            {
                if(Type->Encoding == DW_ATE_signed)
                {
                    Result = "%c";
                }
                else
                {
                    Result = "%d";
                }
            }break;
            case 2:
            {
                Result = "%d";
            }break;
            case 4:
            {
                if(Type->Encoding == DW_ATE_unsigned)
                {
                    Result = "%u";
                }
                else if(Type->Encoding == DW_ATE_float)
                {
                    Result = "%f";
                }
                else
                {
                    Result = "%d";
                }
            }break;
            case 8:
            {
                if(Type->Encoding == DW_ATE_unsigned)
                {
                    Result = "%llu";
                }
                else if(Type->Encoding == DW_ATE_float)
                {
                    Result = "%f";
                }
                else
                {
                    Result = "%lld";
                }
            }break;
            default:
            {
                printf("Unsupported byte size = %d", Type->ByteSize);
                Result = "";
            }break;
        }
    }
    
    return Result;
}

static char *
BaseTypeToFormatStr(size_t BTDIEOffset)
{
    type_flags TFlag = 0;
    di_base_type *Type = FindBaseTypeByOffset(BTDIEOffset, &TFlag);
    
    return BaseTypeToFormatStr(Type, TFlag);
}

static bool
BaseTypeIsFloat(di_base_type *Type)
{
    return Type && Type->Encoding == DW_ATE_float && Type->ByteSize == 4;
}

static bool
BaseTypeIsDoubleFloat(di_base_type *Type)
{
    return Type && Type->Encoding == DW_ATE_float && Type->ByteSize == 8;
}

static di_src_file *
FindSourceFile(char *Path)
{
    di_src_file *Result = 0x0;
    
    for(u32 I = 0; I < DISourceFilesCount; I++)
    {
        if(StringsMatch(Path, DISourceFiles[I].Path))
        {
            Result = &DISourceFiles[I];
            break;
        }
    }
    
    return Result;
}

static di_src_file *
PushSourceFile(char *Path)
{
    di_src_file *Result = 0x0;
    
    Result = &DISourceFiles[DISourceFilesCount++];
    
    Result->Path = strdup(Path);
    Result->Content = DumpFile(Path);
    Result->LineCount = StringCountChar(Result->Content, '\n');
    
    return Result;
}

static di_src_file *
GetSourceFile(char *Path)
{
    di_src_file *Result = 0x0;
    
    Result = FindSourceFile(Path);
    
    if(!Result)
    {
        Result = PushSourceFile(Path);
    }
    
    return Result;
}

static u32
SrcFileAssociatePath(char *Path)
{
    u32 Result = MAX_DI_SOURCE_FILES + 1;
    
    assert(Path);
    for(u32 I = 0; I < DISourceFilesCount; I++)
    {
        if(StringsMatch(Path, DISourceFiles[I].Path))
        {
            Result = I;
            break;
        }
    }
    
    if(DISourceFilesCount == 0 || Result == MAX_DI_SOURCE_FILES + 1)
    {
        PushSourceFile(Path);
        Result = DISourceFilesCount - 1;
    }
    
    return Result;
}

static address_range
AddressRangeCurrentAndNextLine()
{
    address_range Result = {};
    
    di_src_line *Current = LineTableFindByAddress(Regs.rip);
    for(u32 I = 0; I < DISourceLinesCount; I++)
    {
        if(DISourceLines[I].Address == Current->Address)
        {
            for(;;I++)
            {
                if(DISourceLinesCount == I + 1)
                {
                    di_function *Func = FindFunctionConfiningAddress(Current->Address);
                    Result.Start = Current->Address;
                    // TODO(mateusz): I think this will be different, in that it will use 
                    // the lexical scopes
                    Result.End = Func->DIFuncLexScope.HighPC;
                    goto end;
                }
                else
                {
                    di_src_line *Next = &DISourceLines[I];
                    if(Next->LineNum != Current->LineNum)
                    {
                        //printf("Next->LineNum = %d, Current->LineNum = %d\n",Next->LineNum, Current->LineNum);
                        //printf("Next->Address = %lX, Current->Address = %lX\n",Next->Address, Current->Address);
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
    size_t Result = 0;
    
    for(u32 I = 0; I < DIFuctionsCount; I++)
    {
        if(StringsMatch(DIFunctions[I].Name, "main"))
        {
            Result = DIFunctions[I].DIFuncLexScope.LowPC;
            break;
        }
    }
    
    return Result;
}

static size_t
GetDebugeeLoadAddress(i32 DebugeePID)
{
    char Path[64] = {};
    sprintf(Path, "/proc/%d/maps", DebugeePID);
    
    char AddrStr[16] = {};
    FILE *FileHandle = fopen(Path, "r");
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
DWARFReadDIEs(Dwarf_Debug Debug, Dwarf_Die DIE, arena *DIArena)
{
    Dwarf_Error Error_ = {};
    Dwarf_Error *Error = &Error_;
    Dwarf_Die CurrentDIE = DIE;
    
    Dwarf_Half Tag = 0;
    assert(dwarf_tag(CurrentDIE, &Tag, Error) == DW_DLV_OK);
    
    switch(Tag)
    {
        case DW_TAG_compile_unit:
        {
            //printf("libdwarf: Compile Unit\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_compile_unit *CompUnit = &DICompileUnits[DICompileUnitsCount++];
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                
                switch(AttrTag)
                {
                    case DW_AT_name:
                    {
                        char *Name = 0x0;
                        DWARF_CALL(dwarf_formstring(Attribute, &Name, Error));
                        
                        u32 Size = strlen(Name) + 1;
                        CompUnit->Name = ArrayPush(DIArena, char, Size);
                        StringCopy(CompUnit->Name, Name);
                    }break;
                    case DW_AT_low_pc:
                    {
                        Dwarf_Addr *WritePoint = (Dwarf_Addr *)&CompUnit->LowPC;
                        DWARF_CALL(dwarf_formaddr(Attribute, WritePoint, Error));
                    }break;
                    case DW_AT_high_pc:
                    {
                        Dwarf_Addr *WritePoint = (Dwarf_Addr *)&CompUnit->HighPC;
                        
                        Dwarf_Half Form = 0;
                        Dwarf_Form_Class FormType = {};
                        DWARF_CALL(dwarf_highpc_b(DIE, WritePoint, &Form, &FormType, 0x0));
                        if (FormType == DW_FORM_CLASS_CONSTANT) {
                            CompUnit->HighPC += CompUnit->LowPC;
                        }
                        
                    }break;
                    case DW_AT_ranges:
                    {
                        assert(false);
                        CompUnit->Flags |= DI_COMP_UNIT_HAS_RANGES;
                    }break;
                    default:
                    {
                        bool ignored = AttrTag == DW_AT_producer ||
                            AttrTag == DW_AT_comp_dir ||
                            AttrTag == DW_AT_stmt_list || AttrTag == DW_AT_language;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            printf("CompUnit Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
            
            Dwarf_Unsigned Version = 0;
            Dwarf_Small TableType = 0;
            Dwarf_Line_Context LineCtx = 0;
            DWARF_CALL(dwarf_srclines_b(DIE, &Version, &TableType, &LineCtx, Error));
            
            Dwarf_Line *LineBuffer = 0;
            Dwarf_Signed LineCount = 0;
            DWARF_CALL(dwarf_srclines_from_linecontext(LineCtx, &LineBuffer, &LineCount, Error));
            
            for (i32 I = 0; I < LineCount; ++I) {
                Dwarf_Addr LineAddr = 0;
                Dwarf_Unsigned FileNum = 0;
                Dwarf_Unsigned LineNum = 0;
                char *LineSrcFile = 0;
                
                DWARF_CALL(dwarf_lineno(LineBuffer[I], &LineNum, Error));
                DWARF_CALL(dwarf_line_srcfileno(LineBuffer[I], &FileNum, Error));
                if (FileNum) {
                    FileNum -= 1;
                }
                
                DWARF_CALL(dwarf_lineaddr(LineBuffer[I], &LineAddr, Error));
                DWARF_CALL(dwarf_linesrc(LineBuffer[I], &LineSrcFile, Error));
                
                di_src_line *LTEntry = &DISourceLines[DISourceLinesCount++];
                LTEntry->Address = LineAddr;
                LTEntry->LineNum = LineNum;
                LTEntry->SrcFileIndex = SrcFileAssociatePath(LineSrcFile);
            }
        }break;
        case DW_TAG_subprogram:
        {
            //printf("Subprogram\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_function *Func = &DIFunctions[DIFuctionsCount++];
            assert(Func->DILexScopeCount == 0);
            di_lexical_scope *LexScope = &Func->DIFuncLexScope;
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                
                switch(AttrTag)
                {
                    case DW_AT_name:
                    {
                        char *Name = 0x0;
                        DWARF_CALL(dwarf_formstring(Attribute, &Name, Error));
                        
                        u32 Size = strlen(Name) + 1;
                        Func->Name = ArrayPush(DIArena, char, Size);
                        StringCopy(Func->Name, Name);
                    }break;
                    case DW_AT_type:
                    {
                        Dwarf_Off Offset = 0;
                        DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                        
                        Func->TypeOffset = Offset;
                    }break;
                    case DW_AT_low_pc:
                    {
                        Dwarf_Addr *WritePoint = (Dwarf_Addr *)&LexScope->LowPC;
                        DWARF_CALL(dwarf_formaddr(Attribute, WritePoint, Error));
                    }break;
                    case DW_AT_high_pc:
                    {
                        Dwarf_Addr *WritePoint = (Dwarf_Addr *)&LexScope->HighPC;
                        
                        Dwarf_Half Form = 0;
                        Dwarf_Form_Class FormType = {};
                        DWARF_CALL(dwarf_highpc_b(DIE, WritePoint, &Form, &FormType, 0x0));
                        if (FormType == DW_FORM_CLASS_CONSTANT) {
                            LexScope->HighPC += LexScope->LowPC;
                        }
                    }break;
                    case DW_AT_frame_base:
                    {
                        Dwarf_Loc_Head_c LocListHead = {};
                        Dwarf_Unsigned LocCount = 0;
                        DWARF_CALL(dwarf_get_loclist_c(Attribute, &LocListHead, &LocCount, Error));
                        
                        assert(LocCount == 1);
                        for(u32 I = 0; I < LocCount; I++)
                        {
                            Dwarf_Small LLEOut = 0;
                            Dwarf_Addr LowPC = 0;
                            Dwarf_Addr HighPC = 0;
                            Dwarf_Unsigned LocListCountOut = 0;
                            Dwarf_Locdesc_c IDK = 0;
                            Dwarf_Small LocListSourceOut = 0;
                            Dwarf_Unsigned ExpressionOffsetOut = 0;
                            Dwarf_Unsigned LocDescOffsetOut = 0;
                            
                            DWARF_CALL(dwarf_get_locdesc_entry_c(LocListHead, I, &LLEOut, &LowPC, &HighPC, &LocListCountOut, &IDK, &LocListSourceOut, &ExpressionOffsetOut, 
                                                                 &LocDescOffsetOut, Error));
                            
                            Dwarf_Small AtomOut = 0;
                            Dwarf_Unsigned Operand1 = 0;
                            Dwarf_Unsigned Operand2 = 0;
                            Dwarf_Unsigned Operand3 = 0;
                            Dwarf_Unsigned OffsetBranch = 0;
                            DWARF_CALL(dwarf_get_location_op_value_c(IDK, I, &AtomOut, &Operand1, &Operand2, &Operand3, &OffsetBranch, Error));
                            
                            //printf("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                            
                            assert(AtomOut == DW_OP_call_frame_cfa);
                            Func->FrameBaseIsCFA = true;
                        }
                    }break;
                    default:
                    {
                        bool ignored = AttrTag == DW_AT_decl_file ||
                            AttrTag == DW_AT_decl_line ||
                            AttrTag == DW_AT_decl_column || AttrTag == DW_AT_prototyped ||
                            AttrTag == DW_AT_GNU_all_call_sites ||
                            AttrTag == DW_AT_external ||
                            AttrTag == DW_AT_GNU_all_tail_call_sites ||
                            AttrTag == DW_AT_sibling;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            printf("Func Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_lexical_block:
        {
            //printf("libdwarf: Lexical block\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            assert(DIFuctionsCount);
            di_function *Func = &DIFunctions[DIFuctionsCount - 1];
            di_lexical_scope *LexScope = &Func->DILexScopes[Func->DILexScopeCount++];
            
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                
                switch(AttrTag)
                {
                    case DW_AT_ranges:
                    {
                        Dwarf_Ranges *Ranges = 0x0;
                        Dwarf_Signed RangesCount = 0;
                        Dwarf_Unsigned ByteCount = 0;
                        
                        Dwarf_Off DebugRangesOffset = 0;
                        DWARF_CALL(dwarf_global_formref(Attribute, &DebugRangesOffset, Error));
                        
                        DWARF_CALL(dwarf_get_ranges_a(Debug, DebugRangesOffset, DIE, &Ranges,
                                                      &RangesCount, &ByteCount, Error));
                        
                        LexScope->RangesLowPCs = ArrayPush(DIArena, size_t, RangesCount);
                        LexScope->RangesHighPCs = ArrayPush(DIArena, size_t, RangesCount);
                        
                        di_compile_unit *CU = &DICompileUnits[DICompileUnitsCount - 1];
                        size_t SelectedAddress = 0x0;
                        for(u32 I = 0; I < RangesCount; I++)
                        {
                            switch(Ranges[I].dwr_type)
                            {
                                case DW_RANGES_ENTRY:
                                {
                                    size_t RLowPC = CU->LowPC + Ranges[I].dwr_addr1 + SelectedAddress;
                                    size_t RHighPC = CU->LowPC + Ranges[I].dwr_addr2 + SelectedAddress;
                                    
                                    u32 RIndex = LexScope->RangesCount++;
                                    LexScope->RangesLowPCs[RIndex] = RLowPC;
                                    LexScope->RangesHighPCs[RIndex] = RHighPC;
                                }break;
                                case DW_RANGES_ADDRESS_SELECTION:
                                {
                                    SelectedAddress = Ranges[I].dwr_addr2;
                                }break;
                                case DW_RANGES_END:
                                {
                                    break;
                                }break;
                                default:
                                {
                                    assert(false);
                                };
                            }
                        }
                    }break;
                    case DW_AT_low_pc:
                    {
                        Dwarf_Addr *WritePoint = (Dwarf_Addr *)&LexScope->LowPC;
                        DWARF_CALL(dwarf_formaddr(Attribute, WritePoint, Error));
                    }break;
                    case DW_AT_high_pc:
                    {
                        Dwarf_Addr *WritePoint = (Dwarf_Addr *)&LexScope->HighPC;
                        
                        Dwarf_Half Form = 0;
                        Dwarf_Form_Class FormType = {};
                        DWARF_CALL(dwarf_highpc_b(DIE, WritePoint, &Form, &FormType, 0x0));
                        if (FormType == DW_FORM_CLASS_CONSTANT) {
                            LexScope->HighPC += LexScope->LowPC;
                        }
                    }break;
                    default:
                    {
                        bool ignored = AttrTag == DW_AT_decl_file ||
                            AttrTag == DW_AT_decl_line ||
                            AttrTag == DW_AT_decl_column;
                        
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            printf("Variable Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_variable:
        {
            //printf("Variable\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            // TODO(mateusz): Globals
            if(DIFuctionsCount)
            {
                di_function *Func = &DIFunctions[DIFuctionsCount - 1];
                bool HasLexScopes = Func->DILexScopeCount != 0;
                di_lexical_scope *LexScope = HasLexScopes ? &Func->DILexScopes[Func->DILexScopeCount - 1] : &Func->DIFuncLexScope;
                di_variable *Var = &LexScope->DIVariables[LexScope->DIVariablesCount++];
                for(u32 I = 0; I < AttrCount; I++)
                {
                    Dwarf_Attribute Attribute = AttrList[I];
                    Dwarf_Half AttrTag = 0;
                    DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                    
                    switch(AttrTag)
                    {
                        case DW_AT_name:
                        {
                            char *Name = 0x0;
                            DWARF_CALL(dwarf_formstring(Attribute, &Name, Error));
                            
                            u32 Size = strlen(Name) + 1;
                            Var->Name = ArrayPush(DIArena, char, Size);
                            StringCopy(Var->Name, Name);
                        }break;
                        case DW_AT_type:
                        {
                            Dwarf_Off Offset = 0;
                            DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                            
                            Var->TypeOffset = Offset;
                        }break;
                        case DW_AT_location:
                        {
                            Dwarf_Loc_Head_c LocListHead = {};
                            Dwarf_Unsigned LocCount = 0;
                            DWARF_CALL(dwarf_get_loclist_c(Attribute, &LocListHead, &LocCount, Error));
                            
                            assert(LocCount == 1);
                            
                            for(u32 I = 0; I < LocCount; I++)
                            {
                                Dwarf_Small LLEOut = 0;
                                Dwarf_Addr LowPC = 0;
                                Dwarf_Addr HighPC = 0;
                                Dwarf_Unsigned LocListCountOut = 0;
                                Dwarf_Locdesc_c LocDesc = 0;
                                Dwarf_Small LocListSourceOut = 0;
                                Dwarf_Unsigned ExpressionOffsetOut = 0;
                                Dwarf_Unsigned LocDescOffsetOut = 0;
                                
                                DWARF_CALL(dwarf_get_locdesc_entry_c(LocListHead, I, &LLEOut, &LowPC, &HighPC, &LocListCountOut, &LocDesc, &LocListSourceOut, &ExpressionOffsetOut, 
                                                                     &LocDescOffsetOut, Error));
                                
                                Dwarf_Small AtomOut = 0;
                                Dwarf_Unsigned Operand1 = 0;
                                Dwarf_Unsigned Operand2 = 0;
                                Dwarf_Unsigned Operand3 = 0;
                                Dwarf_Unsigned OffsetBranch = 0;
                                DWARF_CALL(dwarf_get_location_op_value_c(LocDesc, I, &AtomOut, &Operand1, &Operand2, &Operand3, &OffsetBranch, Error));
                                
                                //printf("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                                
                                Var->LocationAtom = AtomOut;
                                Var->Offset = Operand1;
                            }
                        }break;
                        default:
                        {
                            bool ignored = AttrTag == DW_AT_decl_file ||
                                AttrTag == DW_AT_decl_line ||
                                AttrTag == DW_AT_decl_column;
                            
                            if(!ignored)
                            {
                                const char *AttrName = 0x0;
                                DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                                printf("Variable Unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_formal_parameter:
        {
            // NOTE(mateusz): This is copy pasta from the variable code higher up
            //printf("Variable\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            // TODO(mateusz): Globals
            if(DIFuctionsCount)
            {
                di_function *Func = &DIFunctions[DIFuctionsCount - 1];
                di_variable *Param = &Func->DIParams[Func->DIParamsCount++];
                for(u32 I = 0; I < AttrCount; I++)
                {
                    Dwarf_Attribute Attribute = AttrList[I];
                    Dwarf_Half AttrTag = 0;
                    DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                    
                    switch(AttrTag)
                    {
                        case DW_AT_name:
                        {
                            char *Name = 0x0;
                            DWARF_CALL(dwarf_formstring(Attribute, &Name, Error));
                            
                            u32 Size = strlen(Name) + 1;
                            Param->Name = ArrayPush(DIArena, char, Size);
                            StringCopy(Param->Name, Name);
                        }break;
                        case DW_AT_type:
                        {
                            Dwarf_Off Offset = 0;
                            DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                            
                            Param->TypeOffset = Offset;
                        }break;
                        case DW_AT_location:
                        {
                            Dwarf_Loc_Head_c LocListHead = {};
                            Dwarf_Unsigned LocCount = 0;
                            DWARF_CALL(dwarf_get_loclist_c(Attribute, &LocListHead, &LocCount, Error));
                            
                            assert(LocCount == 1);
                            
                            for(u32 I = 0; I < LocCount; I++)
                            {
                                Dwarf_Small LLEOut = 0;
                                Dwarf_Addr LowPC = 0;
                                Dwarf_Addr HighPC = 0;
                                Dwarf_Unsigned LocListCountOut = 0;
                                Dwarf_Locdesc_c LocDesc = 0;
                                Dwarf_Small LocListSourceOut = 0;
                                Dwarf_Unsigned ExpressionOffsetOut = 0;
                                Dwarf_Unsigned LocDescOffsetOut = 0;
                                
                                DWARF_CALL(dwarf_get_locdesc_entry_c(LocListHead, I, &LLEOut, &LowPC, &HighPC, &LocListCountOut, &LocDesc, &LocListSourceOut, &ExpressionOffsetOut, 
                                                                     &LocDescOffsetOut, Error));
                                
                                Dwarf_Small AtomOut = 0;
                                Dwarf_Unsigned Operand1 = 0;
                                Dwarf_Unsigned Operand2 = 0;
                                Dwarf_Unsigned Operand3 = 0;
                                Dwarf_Unsigned OffsetBranch = 0;
                                DWARF_CALL(dwarf_get_location_op_value_c(LocDesc, I, &AtomOut, &Operand1, &Operand2, &Operand3, &OffsetBranch, Error));
                                
                                //printf("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                                
                                Param->LocationAtom = AtomOut;
                                Param->Offset = Operand1;
                            }
                        }break;
                        default:
                        {
                            bool ignored = AttrTag == DW_AT_decl_file ||
                                AttrTag == DW_AT_decl_line ||
                                AttrTag == DW_AT_decl_column;
                            
                            if(!ignored)
                            {
                                const char *AttrName = 0x0;
                                DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                                printf("Variable Unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_base_type:
        {
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_base_type *Type = (di_base_type *)&DIBaseTypes[DIBaseTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            Type->DIEOffset = DIEOffset;
            
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                switch(AttrTag)
                {
                    case DW_AT_name:
                    {
#if 0
                        char *Name = 0x0;
                        DWARF_CALL(dwarf_formstring(Attribute, &Name, Error));
                        printf("%s", Name);
#endif
                    }break;
                    case DW_AT_encoding:
                    {
                        Dwarf_Unsigned Encoding = 0;
                        DWARF_CALL(dwarf_formudata(Attribute, &Encoding, Error));
                        Type->Encoding = Encoding;
                    }break;
                    case DW_AT_byte_size:
                    {
                        Dwarf_Unsigned ByteSize = 0;
                        DWARF_CALL(dwarf_formudata(Attribute, &ByteSize, Error));
                        
                        Type->ByteSize = ByteSize;
                    }break;
                    default:
                    {
                        const char *AttrName = 0x0;
                        DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                        printf("Base Type Unhandled Attribute: %s\n", AttrName);
                    }break;
                }
            }
        }break;
        case DW_TAG_typedef:
        {
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_typedef *Typedef = &DITypedefs[DITypedefsCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            Typedef->DIEOffset = DIEOffset;
            
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                switch(AttrTag)
                {
                    case DW_AT_name:
                    {
                        char *Name = 0x0;
                        DWARF_CALL(dwarf_formstring(Attribute, &Name, Error));
                        
                        u32 Size = strlen(Name) + 1;
                        Typedef->Name = ArrayPush(DIArena, char, Size);
                        StringCopy(Typedef->Name, Name);
                    }break;
                    case DW_AT_type:
                    {
                        Dwarf_Off Offset = 0;
                        DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                        
                        Typedef->ActualTypeOffset = Offset;
                    }break;
                    default:
                    {
                        bool ignored = AttrTag == DW_AT_decl_file ||
                            AttrTag == DW_AT_decl_line ||
                            AttrTag == DW_AT_decl_column;
                        
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            printf("Base Type Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_pointer_type:
        {
            //printf("libdwarf: Pointer Type\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_pointer_type *PType = &DIPointerTypes[DIPointerTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            PType->DIEOffset = DIEOffset;
            
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                switch(AttrTag)
                {
                    case DW_AT_byte_size:
                    {
                        Dwarf_Unsigned ByteSize = 0;
                        DWARF_CALL(dwarf_formudata(Attribute, &ByteSize, Error));
                        
                        assert(ByteSize == sizeof(void *));
                    }break;
                    case DW_AT_type:
                    {
                        Dwarf_Off Offset = 0;
                        DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                        
                        PType->ActualTypeOffset = Offset;
                    }break;
                    default:
                    {
                        assert(!"Not expected TAG!");
                    }break;
                }
            }
            
        }break;
        default:
        {
            const char *TagName = 0x0;
            DWARF_CALL(dwarf_get_TAG_name(Tag, &TagName));
            printf("Unhandled Tag: %s\n", TagName);
        }break;
    }
    
    Dwarf_Die ChildDIE = 0;
    i32 Result = dwarf_child(CurrentDIE, &ChildDIE, Error);
    
    if(Result == DW_DLV_OK)
    { 
        DWARFReadDIEs(Debug, ChildDIE, DIArena);
        Dwarf_Die SiblingDIE = ChildDIE;
        while(Result == DW_DLV_OK)
        {
            CurrentDIE = SiblingDIE;
            Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, Error);
            if(Result == DW_DLV_OK)
            {
                DWARFReadDIEs(Debug, SiblingDIE, DIArena);
            }
            else
            {
                break;
            }
        };
    }
    
    return;
}

static void
DWARFRead()
{
    i32 Fd = open(Debuger.DebugeeProgramPath, O_RDONLY);
    assert(Fd != -1);
    
    Dwarf_Handler ErrorHandle = 0;
    Dwarf_Ptr ErrorArg = 0;
    Dwarf_Error *Error  = 0;
    
    assert(dwarf_init(Fd, DW_DLC_READ, ErrorHandle, ErrorArg, &Debug, Error) == DW_DLV_OK);
    
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    
    DIArena = ArenaCreate(Kilobytes(16));
    
    for(i32 CUCount = 0;;++CUCount) {
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
        
        DWARFReadDIEs(Debug, CurrentDIE, DIArena);
    }
    
    assert(dwarf_finish(Debug, Error) == DW_DLV_OK);
    
    // NOTE(mateusz): This time without finish to preserve it
    assert(dwarf_init(Fd, DW_DLC_READ, ErrorHandle, ErrorArg, &Debug, Error) == DW_DLV_OK);
    Dwarf_Cie *CIEs;
    Dwarf_Signed CIECount;
    Dwarf_Fde *FDEs;
    Dwarf_Signed FDECount;
    DWARF_CALL(dwarf_get_fde_list_eh(Debug, &CIEs, &CIECount, &FDEs, &FDECount, Error));
    
    di_frame_info *Frame = &DIFrameInfo;
    Frame->CIECount = CIECount;
    Frame->FDECount = FDECount;
    Frame->CIEs = CIEs;
    Frame->FDEs = FDEs;
    
    close(Fd);
}

static size_t
DWARFGetCFA(size_t PC)
{
    di_frame_info *Frame = &DIFrameInfo;
    for(u32 J = 0; J < Frame->FDECount; J++)
    {
        Dwarf_Error *Error  = 0;
        Dwarf_Addr FDELowPC = 0;
        Dwarf_Unsigned FDEFunctionLength = 0;
        DWARF_CALL(dwarf_get_fde_range(Frame->FDEs[J], &FDELowPC, &FDEFunctionLength,
                                       0x0, 0x0, 0x0, 0x0, 0x0, Error));
        
        if(AddressBetween(PC, FDELowPC, FDELowPC + FDEFunctionLength - 1))
        {
            Dwarf_Regtable3 Tab3 = {};
            Dwarf_Addr ActualPC = 0;
            DWARF_CALL(dwarf_get_fde_info_for_all_regs3(Frame->FDEs[J], PC, &Tab3, &ActualPC, Error));
            
            Dwarf_Small OffsetRel = Tab3.rt3_cfa_rule.dw_offset_relevant;
            Dwarf_Signed OffsetOut = Tab3.rt3_cfa_rule.dw_offset_or_block_len;
            Dwarf_Half RegnumOut = Tab3.rt3_cfa_rule.dw_regnum;
            
            assert(OffsetRel == 1);
            size_t RegVal = GetRegisterByABINumber(RegnumOut);
            
            //printf("RegVal = %lX, OffsetOut = %llX, RegVal + OffsetOut = %lX\n", RegVal, OffsetOut, (size_t)((ssize_t)RegVal + (ssize_t)OffsetOut));
            return RegVal + OffsetOut;
        }
    }
    
    assert(false);
    return PC;
}

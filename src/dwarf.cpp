debug_info _DI = { };
debug_info *DI = &_DI;

static void
DwarfClearAll()
{
    DwarfCloseSymbolsHandle(&DI->DwarfFd, &DI->Debug);
    DwarfCloseSymbolsHandle(&DI->CFAFd, &DI->CFADebug);

    ArenaDestroy(&DI->Arena);

    memset(DI, 0, sizeof(debug_info));
}

static bool
DwarfOpenSymbolsHandle(i32 *Fd, Dwarf_Debug *Debug)
{
    assert(*Fd == 0);
    *Fd = open(Debugee.ProgramPath, O_RDONLY);
    assert(*Fd != -1);
    
    bool Result = dwarf_init(*Fd, DW_DLC_READ, 0, 0, Debug, 0x0) == DW_DLV_OK;
    
    return Result;
}

static void
DwarfCloseSymbolsHandle(i32 *Fd, Dwarf_Debug *Debug)
{
    if(*Fd)
    {
        assert(dwarf_finish(*Debug, 0x0) == DW_DLV_OK);
        close(*Fd);
        *Fd = 0;
    }
}

static di_src_line *
DwarfFindLineByAddress(size_t Address)
{
    // Try to find it in what we have
    for(u32 I = 0; I < DI->SourceFilesCount; I++)
    {
        di_src_file *File = &DI->SourceFiles[I];
        for(u32 J = 0; J < File->SrcLineCount; J++)
        {
            size_t LineAddress = File->Lines[J].Address;
            if(LineAddress == Address)
            {
                return &File->Lines[J];
            }
            else if(J + 1 < File->SrcLineCount &&
                    Address > LineAddress &&
                    Address < File->Lines[J + 1].Address)
            {
                return &File->Lines[J];
            }
        }
    }

    // If we don't have it, call Dwarf parsing, and search for it
    u32 LineIdx = 0;
    u32 FileIdx = 0;
    bool Found = DwarfLoadSourceFileByAddress(Address, &FileIdx, &LineIdx);
    
    if(Found)
    {
        assert(FileIdx < DI->SourceFilesCount);
        di_src_file *File = &DI->SourceFiles[FileIdx];
        assert(LineIdx < File->SrcLineCount);
        di_src_line *Line = &File->Lines[LineIdx];
        
        return Line;
    }
    
    return 0x0;
}

static di_src_line *
DwarfFindLineByNumber(u32 LineNum, u32 SrcFileIndex)
{
    di_src_file *File = &DI->SourceFiles[SrcFileIndex];
    for(u32 J = 0; J < File->SrcLineCount; J++)
    {
        size_t LineNO = File->Lines[J].LineNum;
        if(LineNO == LineNum)
        {
            return &File->Lines[J];
        }
    }

    return 0x0;
}

static bool
DwarfAddressConfinedByFunction(di_function *Func, size_t Address)
{
    size_t LowPC = Func->FuncLexScope.LowPC;
    size_t HighPC = Func->FuncLexScope.HighPC;

    return AddressBetween(Address, LowPC, HighPC);
}

static di_function *
DwarfFindFunctionByAddress(size_t Address)
{
    di_function *Result = 0x0;
    
    for(u32 I = 0; I < DI->FunctionsCount; I++)
    {
        di_function *Func = &DI->Functions[I];
        if(AddressBetween(Address, Func->FuncLexScope.LowPC, Func->FuncLexScope.HighPC))
        {
            Result = &DI->Functions[I];
            break;
        }
    }
    
    return Result;
}

/* NOTE(mateusz): 

Types like DW_TAG_pointer_type, DW_TAG_typedef, DW_TAG_const_type, DW_TAG_array_type...
are considered as "decorator" types, and only help in displaying the underlaying types.
As underlaying types we understand DW_TAG_base_type or DW_TAG_structure_type.
This function recursivley adds "decorator" types to the flags, and ultimately returns
 void * that depending on the underlaying type is either di_base_type or di_struct_type.

*/

static OrderingType
DIEOffsetPredicate(void *Cmp, void *Search)
{
    OrderingType Result = 0;
    
    size_t CmpVal = *(size_t *)Cmp;
    size_t SearchVal = *(size_t *)Search;

    if(CmpVal == SearchVal)
    {
        Result = ORD_EQ;
    }
    else if(CmpVal < SearchVal)
    {
        Result = ORD_LT;
    }
    else
    {
        Result = ORD_GT;
    }

    return Result;
}

static di_underlaying_type
DwarfFindUnderlayingType(size_t BTDIEOffset)
{
    di_underlaying_type Result = {};

    BinSearchRes SearchResult = BinarySearch(DI->Typedefs, DI->TypedefsCount, offsetof(di_typedef, DIEOffset),
                                               sizeof(di_typedef), DIEOffsetPredicate, (void *)&BTDIEOffset);

    if(SearchResult.Found)
    {
        Result = DwarfFindUnderlayingType(DI->Typedefs[SearchResult.Index].ActualTypeOffset);
        Result.Flags.IsTypedef = 1;
        Result.Name = DI->Typedefs[SearchResult.Index].Name;

        return Result;
    }

    SearchResult = BinarySearch(DI->PointerTypes, DI->PointerTypesCount, offsetof(di_pointer_type, DIEOffset),
                                sizeof(di_pointer_type), DIEOffsetPredicate, (void *)&BTDIEOffset);

    if(SearchResult.Found)
    {
        Result = DwarfFindUnderlayingType(DI->PointerTypes[SearchResult.Index].ActualTypeOffset);
        Result.Flags.IsPointer = 1;
        Result.PointerCount += 1;
        return Result;
    }

    SearchResult = BinarySearch(DI->ConstTypes, DI->ConstTypesCount, offsetof(di_const_type, DIEOffset),
                                sizeof(di_const_type), DIEOffsetPredicate, (void *)&BTDIEOffset);

    if(SearchResult.Found)
    {
        Result = DwarfFindUnderlayingType(DI->ConstTypes[SearchResult.Index].ActualTypeOffset);
        Result.Flags.IsConst = 1;
        return Result;
    }

    SearchResult = BinarySearch(DI->RestrictTypes, DI->RestrictTypesCount, offsetof(di_restrict_type, DIEOffset),
                                sizeof(di_restrict_type), DIEOffsetPredicate, (void *)&BTDIEOffset);

    if(SearchResult.Found)
    {
        Result = DwarfFindUnderlayingType(DI->RestrictTypes[SearchResult.Index].ActualTypeOffset);
        Result.Flags.IsRestrict = 1;
        return Result;
    }

    SearchResult = BinarySearch(DI->ArrayTypes, DI->ArrayTypesCount, offsetof(di_array_type, DIEOffset),
                                sizeof(di_array_type), DIEOffsetPredicate, (void *)&BTDIEOffset);

    if(SearchResult.Found)
    {
        Result = DwarfFindUnderlayingType(DI->ArrayTypes[SearchResult.Index].ActualTypeOffset);
        Result.ArrayUpperBound = DI->ArrayTypes[SearchResult.Index].UpperBound;
        Result.Flags.IsArray = 1;
        return Result;
    }

    SearchResult = BinarySearch(DI->StructTypes, DI->StructTypesCount, offsetof(di_struct_type, DIEOffset),
                                sizeof(di_struct_type), DIEOffsetPredicate, (void *)&BTDIEOffset);

    // Underlaying types
    if(SearchResult.Found)
    {
        Result.Flags.IsStruct = 1;
        Result.Struct = &DI->StructTypes[SearchResult.Index];
        Result.Name = DI->StructTypes[SearchResult.Index].Name;

        return Result;
    }

    SearchResult = BinarySearch(DI->UnionTypes, DI->UnionTypesCount, offsetof(di_union_type, DIEOffset),
                                sizeof(di_union_type), DIEOffsetPredicate, (void *)&BTDIEOffset);

    if(SearchResult.Found)
    {
        Result.Flags.IsUnion = 1;
        Result.Union = &DI->UnionTypes[SearchResult.Index];
        Result.Name = DI->UnionTypes[SearchResult.Index].Name;

        return Result;
    }

    SearchResult = BinarySearch(DI->BaseTypes, DI->BaseTypesCount, offsetof(di_base_type, DIEOffset),
                                sizeof(di_base_type), DIEOffsetPredicate, (void *)&BTDIEOffset);

    if(SearchResult.Found)
    {
        Result.Flags.IsBase = 1;
        Result.Type = &DI->BaseTypes[SearchResult.Index];
        Result.Name = DI->BaseTypes[SearchResult.Index].Name;

        return Result;
    }

    return Result;
}

static di_underlaying_type
DwarfGetVariablesUnderlayingType(di_variable *Var)
{
	di_underlaying_type Result = {};
	
	if(Var->ValidUnderlayingType)
	{
		Result = Var->Underlaying;
	}
	else
	{
		Var->Underlaying = DwarfFindUnderlayingType(Var->TypeOffset);
		Var->ValidUnderlayingType = true;
		Result = Var->Underlaying;
	}

	return Result;
}

static size_t
DwarfGetVariableMemoryAddress(di_variable *Var)
{
    size_t Address = 0x0;
    if(Var->LocationAtom == DW_OP_fbreg)
    {
        size_t CFA = DwarfGetCanonicalFrameAddress(DebugeeGetProgramCounter(&Debugee));
        Address = CFA + Var->Offset;
    }
    else if(Var->LocationAtom == DW_OP_addr)
    {
        Address = Debugee.Flags.PIE ? Var->Offset + Debugee.LoadAddress : Var->Offset;
    }
    else if(Var->LocationAtom >= DW_OP_breg0 && Var->LocationAtom <= DW_OP_breg15)
    {
        size_t Register = RegisterGetByABINumber(Debugee.Regs, Var->LocationAtom - DW_OP_breg0);
        Address = Var->Offset + Register;
    }

    return Address;
}

static u32
DwarfParseTypeStringToBytes(di_underlaying_type *Underlaying, char *String, u8 *Result)
{
    u32 WrittenBytes = 0;

    if(Underlaying->Type->Encoding == DW_ATE_float)
    {
        switch(Underlaying->Type->ByteSize)
        {
        case 4:
        {
            union Float4Int
            {
                float Float;
                u8 Bytes[4];
            };

            Float4Int FI = {};
            FI.Float = atof(String);

            WrittenBytes = sizeof(Float4Int);
            assert(WrittenBytes == 4);
            memcpy(Result, FI.Bytes, WrittenBytes);

            break;
        }
        case 8:
        {
            union Float8Int
            {
                double Float;
                u8 Bytes[8];
            };

            Float8Int FI = {};
            FI.Float = atof(String);

            WrittenBytes = sizeof(Float8Int);
            assert(WrittenBytes == 8);
            memcpy(Result, FI.Bytes, WrittenBytes);

            break;
        }
        default:
        {
            assert(false && "Non default float type.");
            break;
        }
        }
    }
    else
    {
        assert(Underlaying->Type->Encoding == DW_ATE_unsigned || Underlaying->Type->Encoding == DW_ATE_signed);

        switch(Underlaying->Type->ByteSize)
        {
        case 1:
        {
            i64 Val = atol(String);
            WrittenBytes = 1;
            Result[0] = (u8)(Val & 0xff);

            break;
        }
        case 2:
        {
            i64 Val = atol(String);
            WrittenBytes = 2;
            Result[0] = (u8)(Val & 0xff);
            Result[1] = (u8)(Val & 0xff00);

            break;
        }
        case 4:
        {
            i64 Val = atol(String);
            WrittenBytes = 4;
            memcpy(Result, &Val, WrittenBytes);
            break;
        }
        case 8:
        {
            // TODO(mateusz): Do we need these if's?
            if(Underlaying->Type->Encoding == DW_ATE_unsigned)
            {
                i64 Val = atol(String);
                WrittenBytes = 8;
                memcpy(Result, &Val, WrittenBytes);
            }
            else
            {
                char *StrEnd = 0x0;
                u64 Val = strtoull(String, &StrEnd, 10);
                assert(StrEnd);

                WrittenBytes = 8;
                memcpy(Result, &Val, WrittenBytes);
            }
            break;
        }
        default:
        {
            assert(false && "Non default int type.");
            break;
        }
        }
    }

    return WrittenBytes;
}

static scoped_vars
DwarfGetScopedVars(size_t PC)
{
    scoped_vars Result = {};

    di_compile_unit *CU = DwarfFindCompileUnitByAddress(PC);

    if(CU)
    {
        Result.Global = CU->GlobalVariables;
        Result.GlobalCount = CU->GlobalVariablesCount;
    }

    di_function *Func = DwarfFindFunctionByAddress(PC);
    if(Func && Func->FrameBaseIsCFA)
    {
        Result.Param = Func->Params;
        Result.ParamCount = Func->ParamCount;

        //TODO(mateusz): Some variables are missing that way, fix it.
        Result.Local = Func->FuncLexScope.Variables;
        Result.LocalCount = Func->FuncLexScope.VariablesCount;
    }

    return Result;
}

static di_variable *
DwarfFindVariableByNameInScope(scoped_vars Scope, char *Name)
{
    for(u32 I = 0; I < Scope.GlobalCount; I++)
    {
        if(StringMatches(Name, Scope.Global[I].Name))
        {
            return &Scope.Global[I];
        }
    }

    for(u32 I = 0; I < Scope.ParamCount; I++)
    {
        if(StringMatches(Name, Scope.Param[I].Name))
        {
            return &Scope.Param[I];
        }
    }

    for(u32 I = 0; I < Scope.LocalCount; I++)
    {
        if(StringMatches(Name, Scope.Local[I].Name))
        {
            return &Scope.Local[I];
        }
    }

    return 0x0;
}

static char *
DwarfGetTypeStringRepresentation(di_underlaying_type Type, arena *Arena)
{
    char *Result = 0x0;

    char *TypeName = 0x0;
    if(Type.Name)
    {
        TypeName = Type.Name;
    }
    else
    {
        // void type
        if(!Type.Flags.IsBase)
        {
            TypeName = "void";
        }
    }
    u32 NameLen = StringLength(TypeName);

    if(Type.Flags.IsArray)
    {
        Result = ArrayPush(Arena, char, NameLen + 32);
        sprintf(Result, "%s [%ld]", TypeName, Type.ArrayUpperBound + 1);
    }
    else if(Type.Flags.IsPointer)
    {
        Result = ArrayPush(Arena, char, NameLen + Type.PointerCount + 16);
        sprintf(Result, "%s *", TypeName);
        
        for(u32 I = 0; I < Type.PointerCount - 1; I++)
        {
            StringConcat(Result, "*");
        }
    }
    else
    {
        Result = ArrayPush(Arena, char, NameLen + 1);
        StringCopy(Result, TypeName);
    }

    return Result;
}


static char *
DwarfBaseTypeToFormatStr(di_base_type *Type, type_flags TFlag)
{
    char *Result = "";
    
    if(Type && (TFlag.IsPointer))
    {
        Result = "%p";
    }
    else if(Type)
    {
        switch(Type->ByteSize)
        {
            case 1:
            {
                if(Type->Encoding == DW_ATE_signed_char)
                {
                    Result = "%c";
                }
                else
                {
                    Result = "%u";
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
                LOG_DWARF("Unsupported byte size = %d", Type->ByteSize);
                Result = "";
            }break;
        }
    }
    
    return Result;
}

static bool
DwarfBaseTypeIsFloat(di_base_type *Type)
{
    return Type && Type->Encoding == DW_ATE_float && Type->ByteSize == 4;
}

static bool
DwarfBaseTypeIsDoubleFloat(di_base_type *Type)
{
    return Type && Type->Encoding == DW_ATE_float && Type->ByteSize == 8;
}

static di_struct_member *
DwarfStructGetMemberByName(di_struct_type *Type, char *Name)
{
    di_struct_member *Result = 0x0;
    for(u32 I = 0; I < Type->MembersCount; I++)
    {
        if(StringMatches(Name, Type->Members[I].Name))
        {
            Result = &Type->Members[I];
            break;
        }
    }

    return Result;
}

static di_union_member *
DwarfUnionGetMemberByName(di_union_type *Type, char *Name)
{
    di_union_member *Result = 0x0;

    for(u32 I = 0; I < Type->MembersCount; I++)
    {
        if(StringMatches(Name, Type->Members[I].Name))
        {
            Result = &Type->Members[I];
            break;
        }
    }

    return Result;
}

static bool
DwarfAddressConfinedByLexicalScope(di_lexical_scope *LexScope, size_t Address)
{
    bool Result = false;
    if(LexScope->RangesCount == 0)
    {
        Result = AddressBetween(Address, LexScope->LowPC, LexScope->HighPC - 1);
    }
    else
    {
        for(u32 RIndex = 0; RIndex < LexScope->RangesCount; RIndex++)
        {
            if(AddressBetween(Address, LexScope->RangesLowPCs[RIndex], LexScope->RangesHighPCs[RIndex]))
            {
                Result = true;
                break;
            }
        }
    }

    return Result;
}

static bool
DwarfAddressConfinedByCompileUnit(di_compile_unit *CU, size_t Address)
{
    bool Result = false;

    for(u32 I = 0; I < CU->RangesCount; I++)
    {
        if(AddressBetween(Address, CU->RangesLowPCs[I], CU->RangesHighPCs[I]))
        {
            Result = true;
            break;
        }
    }

    return Result;
}

static di_compile_unit *
DwarfFindCompileUnitByAddress(size_t Address)
{
    di_compile_unit *Result = 0x0;

    for(u32 I = 0; I < DI->CompileUnitsCount; I++)
    {
        di_compile_unit *CU = &DI->CompileUnits[I];
        if(DwarfAddressConfinedByCompileUnit(CU, Address))
        {
            Result = CU;
            break;
        }
    }

    return Result;
}

static di_src_file *
DwarfFindSourceFileByPath(char *Path)
{
    di_src_file *Result = 0x0;
    
    for(u32 I = 0; I < DI->SourceFilesCount; I++)
    {
        if(StringMatches(Path, DI->SourceFiles[I].Path))
        {
            Result = &DI->SourceFiles[I];
            break;
        }
    }
    
    return Result;
}

static di_src_file *
DwarfPushSourceFile(char *Path, u32 SrcLineCount)
{
    di_src_file *Result = 0x0;
    
    Result = &DI->SourceFiles[DI->SourceFilesCount++];
    
    Result->Path = StringDuplicate(&DI->Arena, Path);
    char *FileCont = DumpFile(&DI->Arena, Path);
    u32 LineCount = StringSplit(FileCont, '\n');

    Result->ContentLineCount = LineCount;
    Result->Content = ArrayPush(&DI->Arena, char *, LineCount);

    char *Line = FileCont;
    for(u32 I = 0; I < LineCount; I++)
    {
        Result->Content[I] = Line;
        Line = StringSplitNext(Line);
    }

    Result->SrcLineCount = 0;
    Result->Lines = ArrayPush(&DI->Arena, di_src_line, SrcLineCount);
    
    return Result;
}

static Dwarf_Die
DwarfFindDIEByOffset(Dwarf_Debug Debug, Dwarf_Die DIE, size_t Offset)
{
    Dwarf_Off DIEOffset = 0;
    DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, 0x0));
    Dwarf_Off OverallOffset = 0;
    DWARF_CALL(dwarf_dieoffset(DIE, &OverallOffset, 0x0));
    
    if((OverallOffset - DIEOffset) == Offset)
    {
        return DIE;
    }
    else
    {
        Dwarf_Die ChildDIE = 0;
        i32 Result = dwarf_child(DIE, &ChildDIE, 0x0);
        
        if(Result == DW_DLV_OK)
        { 
            return DwarfFindDIEByOffset(Debug, ChildDIE, Offset);
            Dwarf_Die SiblingDIE = ChildDIE;
            while(Result == DW_DLV_OK)
            {
                DIE = SiblingDIE;
                Result = dwarf_siblingof(Debug, DIE, &SiblingDIE, 0x0);
                if(Result == DW_DLV_OK)
                {
                    return DwarfFindDIEByOffset(Debug, SiblingDIE, Offset);
                }
                else
                {
                    return 0x0;
                }
            };
        }
    }
    
    return 0x0;
}

static u32
DwarfCountSourceFileLines(Dwarf_Line *Lines, u32 LineCount, u32 FileIdx)
{
    u32 Result = 0;

    for(u32 I = 0; I < LineCount; I++)
    {
        Dwarf_Unsigned CheckFileNum = 0;
        DWARF_CALL(dwarf_line_srcfileno(Lines[I], &CheckFileNum, 0x0));

        if(CheckFileNum == FileIdx)
        {
            Result += 1;
        }
    }

    return Result;
}

static void
DwarfLoadSourceFileByIndex(Dwarf_Line *Lines, u32 LineCount, di_src_file *File, u32 FileIdx, u32 LineNum = 0, u32 *LineIdxOut = 0x0)
{
    for(u32 I = 0; I < LineCount; I++)
    {
        Dwarf_Unsigned CheckFileNum = 0;
        DWARF_CALL(dwarf_line_srcfileno(Lines[I], &CheckFileNum, 0x0));

        if(CheckFileNum == FileIdx)
        {
            di_src_line Line = {};
            Line.SrcFileIndex = File - DI->SourceFiles;
            Dwarf_Unsigned Addr = 0;
            Dwarf_Unsigned LineNO = 0;
            DWARF_CALL(dwarf_lineaddr(Lines[I], &Addr, 0x0));
            DWARF_CALL(dwarf_lineno(Lines[I], &LineNO, 0x0));

            if(LineIdxOut && LineNO == LineNum)
            {
                *LineIdxOut = File->SrcLineCount;
            }

            Line.Address = Debugee.Flags.PIE ? Addr + Debugee.LoadAddress : Addr;
            Line.LineNum = LineNO;

            Dwarf_Signed LineOffset = 0;
            DWARF_CALL(dwarf_lineoff(Lines[I], &LineOffset, 0x0));
            
            LOG_DWARF("Pair Addr - LineNO => %llx - %llu, with offset = %llx\n", Addr, LineNO, LineOffset);

            File->Lines[File->SrcLineCount++] = Line;
        }
    }
}

static void
DwarfLoadSourceFileFromCU(di_compile_unit *CU, di_exec_src_file *File)
{
    assert(DwarfOpenSymbolsHandle(&DI->DwarfFd, &DI->Debug));
    
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    Dwarf_Error *Error = 0x0;
    
    Dwarf_Die SearchDie = 0x0;
    for(;;)
    {
        i32 ResultI = dwarf_next_cu_header(DI->Debug, &CUHeaderLength,
                                           &Version, &AbbrevOffset, &AddressSize,
                                           &NextCUHeader, Error);
                
        assert(ResultI != DW_DLV_ERROR);
                
        Dwarf_Die CurrentDIE = 0;
        ResultI = dwarf_siblingof(DI->Debug, 0, &CurrentDIE, Error);
        assert(ResultI != DW_DLV_ERROR && ResultI != DW_DLV_NO_ENTRY);
                
        SearchDie = DwarfFindDIEByOffset(DI->Debug, CurrentDIE, CU->Offset);
        if(SearchDie)
        {
            break;
        }
    }

    if(SearchDie)
    {
        Dwarf_Unsigned Version = 0;
        Dwarf_Small TableType = 0;
        Dwarf_Line_Context LineCtx = 0;
        DWARF_CALL(dwarf_srclines_b(SearchDie, &Version, &TableType, &LineCtx, 0x0));
                
        Dwarf_Line *LineBuffer = 0;
        Dwarf_Signed LineCount = 0;
        DWARF_CALL(dwarf_srclines_from_linecontext(LineCtx, &LineBuffer, &LineCount, Error));
        
        u32 LinesMatching = DwarfCountSourceFileLines(LineBuffer, LineCount, File->DwarfIndex);

        char FileName[NAME_MAX] = {};
        sprintf(FileName, "%s/%s", File->Dir, File->Name);
        LOG_DWARF("Source path is [%s]\n", FileName);

        di_src_file *NewFile = DwarfPushSourceFile(FileName, LinesMatching);
        LOG_DWARF("Pushing source file %s\n", FileName);

        DwarfLoadSourceFileByIndex(LineBuffer, LineCount, NewFile, File->DwarfIndex);
    }

    DwarfCloseSymbolsHandle(&DI->DwarfFd, &DI->Debug);
}

static bool
DwarfLoadSourceFileByAddress(size_t Address, u32 *FileIdxOut, u32 *LineIdxOut)
{
    bool Result = false;
    
    assert(DwarfOpenSymbolsHandle(&DI->DwarfFd, &DI->Debug));

    LOG_DWARF("Loading source that contains address %lx\n", Address);
    
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    Dwarf_Error *Error = 0x0;
    
    size_t CUDIEOffset = 0;
    bool CUFound = false;
    if(DI->CompileUnitsCount > 0)
    {
        LOG_DWARF("Searching for CU\n");
        for(u32 I = 0; I < DI->CompileUnitsCount; I++)
        {
            di_compile_unit *CompUnit = &DI->CompileUnits[I];
            for(u32 RI = 0; RI < CompUnit->RangesCount; RI++)
            {
                LOG_DWARF("%lx, %lx, Address = %lx\n", CompUnit->RangesLowPCs[RI], CompUnit->RangesHighPCs[RI], Address);
                ssize_t LowPC = CompUnit->RangesLowPCs[RI];
                ssize_t HighPC = CompUnit->RangesHighPCs[RI];
                LOG_DWARF("compunit, LOWPC, HIGHPC = %lx, %lx, Address = %lx\n", LowPC, HighPC, Address);
                
                if(AddressBetween(Address, LowPC, HighPC))
                {
                    CUDIEOffset = CompUnit->Offset;
                    CUFound = true;
                    LOG_DWARF("LowPC is %lx, HighPC is %lx\n", LowPC, HighPC);
                }
            }
        }

        if(CUFound)
        {
            LOG_DWARF("Found CU with offset %lx\n", CUDIEOffset);
            LOG_DWARF("Searching for that DIE\n");

            Dwarf_Die SearchDie = 0x0;
            
            for(;;)
            {
                i32 ResultI = dwarf_next_cu_header(DI->Debug, &CUHeaderLength,
                                                   &Version, &AbbrevOffset, &AddressSize,
                                                   &NextCUHeader, Error);
                
                assert(ResultI != DW_DLV_ERROR);
                
                Dwarf_Die CurrentDIE = 0;
                Result = dwarf_siblingof(DI->Debug, 0, &CurrentDIE, Error);
                assert(ResultI != DW_DLV_ERROR && ResultI != DW_DLV_NO_ENTRY);
                
                SearchDie = DwarfFindDIEByOffset(DI->Debug, CurrentDIE, CUDIEOffset);
                if(SearchDie)
                {
                    break;
                }
            }
            
            if(SearchDie)
            {
                LOG_DWARF("Found DIE\n");
                Dwarf_Half Tag = 0;
                DWARF_CALL(dwarf_tag(SearchDie, &Tag, 0x0));
                assert(Tag == DW_TAG_compile_unit);
                
                Dwarf_Unsigned Version = 0;
                Dwarf_Small TableType = 0;
                Dwarf_Line_Context LineCtx = 0;
                DWARF_CALL(dwarf_srclines_b(SearchDie, &Version, &TableType, &LineCtx, 0x0));
                
                Dwarf_Line *LineBuffer = 0;
                Dwarf_Signed LineCount = 0;
                DWARF_CALL(dwarf_srclines_from_linecontext(LineCtx, &LineBuffer, &LineCount, Error));
                
                LOG_DWARF("There are %lld source lines\n", LineCount);
                LOG_DWARF("Iterating over %lld lines\n", LineCount);
                for(i32 I = 0; I < LineCount; ++I)
                {
                    Dwarf_Addr LineAddr = 0;
                    Dwarf_Unsigned FileNum = 0;
                    Dwarf_Unsigned LineNum = 0;
                    
                    DWARF_CALL(dwarf_lineaddr(LineBuffer[I], &LineAddr, Error));
                    DWARF_CALL(dwarf_lineno(LineBuffer[I], &LineNum, Error));
                    DWARF_CALL(dwarf_line_srcfileno(LineBuffer[I], &FileNum, Error));

                    // NOTE(mateusz): LineAddresses are as offsets, we need them in the address
                    // space of the exectuable.
                    LineAddr = Debugee.Flags.PIE ? LineAddr + Debugee.LoadAddress : LineAddr;
                    
                    if(Address == LineAddr)
                    {
                        // Dump this file into memory
                        LOG_DWARF("Address = %lx, LineAddr = %llx, FileNum = %llu, LineNum = %llu\n", Address, LineAddr, FileNum, LineNum);

                        char *FileName = 0x0;
                        DWARF_CALL(dwarf_linesrc(LineBuffer[I], &FileName, Error));
                        LOG_DWARF("Address %lx, FileName %p [%s]\n", Address, (void *)FileName, FileName);
                        u32 LinesMatching = DwarfCountSourceFileLines(LineBuffer, LineCount, FileNum);

                        di_src_file *File = DwarfPushSourceFile(FileName, LinesMatching);
                        LOG_DWARF("Pushing source file %s\n", FileName);

                        DwarfLoadSourceFileByIndex(LineBuffer, LineCount, File, FileNum, LineNum, LineIdxOut);

                        *FileIdxOut = DI->SourceFilesCount - 1;

                        Result = true;
                        break;
                    }
                }
            }
        }
    }
    
    DwarfCloseSymbolsHandle(&DI->DwarfFd, &DI->Debug);
    
    return Result;
}

static address_range
DwarfGetAddressRangeUntilNextLine(size_t StartAddress)
{
    address_range Result = {};
    
    di_src_line *Current = DwarfFindLineByAddress(StartAddress);
    if(!Current)
    {
        LOG_DWARF("Didn't find line with address = %lx\n", StartAddress);
        assert(false);
    }
    di_src_file *File = &DI->SourceFiles[Current->SrcFileIndex];
LOG_DWARF("Current->Address = %lx, Current->SrcFileIndex = %d\n", Current->Address, Current->SrcFileIndex);

    u32 LineIdx = Current - File->Lines;
    for(u32 I = LineIdx; I < File->SrcLineCount; I++)
    {
        if(File->SrcLineCount == I + 1)
        {
            di_function *Func = DwarfFindFunctionByAddress(Current->Address);
            Result.Start = Current->Address;
            Result.End = Func->FuncLexScope.HighPC;
            break;
        }
        else
        {
            di_src_line *Next = &File->Lines[I];
            if(Next->LineNum != Current->LineNum && Next->Address != Current->Address)
            {
                LOG_DWARF("Next->LineNum = %d, Current->LineNum = %d\n",Next->LineNum, Current->LineNum);
                LOG_DWARF("Next->Address = %lX, Current->Address = %lX\n",Next->Address, Current->Address);
                Result.Start = Current->Address;
                Result.End = Next->Address;

                break;
            }
        }
    }
    
    return Result;
}

static size_t
DwarfFindEntryPointAddress()
{
    size_t Result = 0;
    
    for(u32 I = 0; I < DI->FunctionsCount; I++)
    {
        if(StringMatches(DI->Functions[I].Name, "main"))
        {
            LOG_DWARF("entrypoint: %s\n", DI->Functions[I].Name);
            Result = DI->Functions[I].FuncLexScope.LowPC;
            break;
        }
    }
    
    return Result;
}

static bool
DwarfIsExectuablePIE()
{
    bool Result = false;

    Elf *ElfHandle = 0x0;
    int BinaryFD = open(Debugee.ProgramPath, O_RDONLY);
    assert(BinaryFD > 0);

    assert(elf_version(EV_CURRENT) != EV_NONE);
    assert((ElfHandle = elf_begin(BinaryFD, ELF_C_READ, 0x0)));

    Elf64_Ehdr *ElfHeader = elf64_getehdr(ElfHandle);

    // Based on
    // https://stackoverflow.com/questions/34519521/why-does-gcc-create-a-shared-object-instead-of-an-executable-binary-according-to/55704865#55704865
    if(ElfHeader->e_type == ET_EXEC)
    {
        // non PIE
    }
    else if(ElfHeader->e_type == ET_DYN)
    {
        Elf_Scn *ElfScn = 0x0;
        Elf64_Dyn *DynamicSection = 0x0;
        while((ElfScn = elf_nextscn(ElfHandle, ElfScn)))
        {
            Elf64_Shdr *SectionHeader = elf64_getshdr(ElfScn);
            if(SectionHeader->sh_type == SHT_DYNAMIC)
            {
                Elf_Data *Data = elf_getdata(ElfScn, 0x0);
                DynamicSection = (Elf64_Dyn *)Data->d_buf;
            }
        }

        u32 I = 0;
        while(DynamicSection[I].d_tag != DT_NULL)
        {
            if(DynamicSection[I].d_tag == DT_FLAGS_1 && DynamicSection[I].d_un.d_val & DF_1_PIE)
            {
                // It's a PIE
                Result = true;
                break;
            }
            I++;
        }
    }

    elf_end(ElfHandle);
    
    return Result;
}

static void
DwarfReadDIE(Dwarf_Debug Debug, Dwarf_Die DIE)
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
            LOG_DWARF("libdwarf: Compile Unit\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_compile_unit *CompUnit = &DI->CompileUnits[DI->CompileUnitsCount++];

            Dwarf_Off OverallOffset = 0;
            DWARF_CALL(dwarf_dieoffset(DIE, &OverallOffset, Error));
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, 0x0));
            
            CompUnit->Offset = OverallOffset - DIEOffset;
            
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
                        CompUnit->Name = ArrayPush(&DI->Arena, char, Size);
                        StringCopy(CompUnit->Name, Name);
                    }break;
                    case DW_AT_low_pc:
                    {
                        /* NOTE(mateusz):

Taken from glfwFramework:

< 0><0x0000000b>  DW_TAG_compile_unit
                    DW_AT_producer              GNU C++14 10.2.1 20201016 (Red Hat 10.2.1-6) -mtune=generic -march=x86-64 -g -std=gnu++14
                    DW_AT_language              DW_LANG_C_plus_plus
                    DW_AT_name                  /home/mateusz/src/cpp/opengl/glfwFramework/main.cc
                    DW_AT_comp_dir              /home/mateusz/src/cpp/opengl/glfwFramework/build
                    DW_AT_ranges                0x00000150
                ranges: 4 at .debug_ranges offset 336 (0x00000150) (64 bytes)
                        [ 0] range entry    0x0042c7e6 0x00444e61
                        [ 1] range entry    0x00444e61 0x00444e84
                        [ 2] range entry    0x00444e84 0x00444eac
                        [ 3] range end      0x00000000 0x00000000
                    DW_AT_low_pc                0x00000000
                    DW_AT_stmt_list             0x00000000

sometimes there are ranges which also have a low_pc which I guess is always zero
it's weird so I'm just going to assume that it's always zero and if already
ranges have been read then don't read the low-high

*/
                        if(CompUnit->RangesCount == 0)
                        {
                            CompUnit->RangesLowPCs = ArrayPush(&DI->Arena, size_t, 1);
                            CompUnit->RangesCount = 1;
                            Dwarf_Addr *WritePoint = (Dwarf_Addr *)CompUnit->RangesLowPCs;
                            DWARF_CALL(dwarf_formaddr(Attribute, WritePoint, Error));
                        }
                        else
                        {
                            Dwarf_Addr WritePoint;
                            DWARF_CALL(dwarf_formaddr(Attribute, &WritePoint, Error));
                            assert(WritePoint == 0x0);
                        }
                    }break;
                    case DW_AT_high_pc:
                    {
                        if(CompUnit->RangesCount == 0 || (CompUnit->RangesCount == 1 && CompUnit->RangesLowPCs))
                        {
                            CompUnit->RangesHighPCs = ArrayPush(&DI->Arena, size_t, 1);
                            Dwarf_Addr *WritePoint = (Dwarf_Addr *)CompUnit->RangesHighPCs;

                            Dwarf_Half Form = 0;
                            Dwarf_Form_Class FormType = {};
                            DWARF_CALL(dwarf_highpc_b(DIE, WritePoint, &Form, &FormType, 0x0));
                            if(FormType == DW_FORM_CLASS_CONSTANT)
                            {
                                CompUnit->RangesHighPCs[0] += CompUnit->RangesLowPCs[0];
                            }
                        }
                        else
                        {
                            assert(!"READ THE NOTE ABOVE");
                        }
                        
                    }break;
                    case DW_AT_ranges:
                    {
                        Dwarf_Ranges *Ranges = 0x0;
                        Dwarf_Signed RangesCount = 0;
                        Dwarf_Unsigned ByteCount = 0;
                        CompUnit->RangesCount = 0;
                        Dwarf_Off DebugRangesOffset = 0;
                        DWARF_CALL(dwarf_global_formref(Attribute, &DebugRangesOffset, Error));
                        
                        DWARF_CALL(dwarf_get_ranges_a(Debug, DebugRangesOffset, DIE, &Ranges,
                                                      &RangesCount, &ByteCount, Error));
                        
                        CompUnit->RangesLowPCs = ArrayPush(&DI->Arena, size_t, RangesCount);
                        CompUnit->RangesHighPCs = ArrayPush(&DI->Arena, size_t, RangesCount);
                        
                        size_t SelectedAddress = 0x0;
                        for(u32 I = 0; I < RangesCount; I++)
                        {
                            switch(Ranges[I].dwr_type)
                            {
                                case DW_RANGES_ENTRY:
                                {
                                    size_t RLowPC = Ranges[I].dwr_addr1 + SelectedAddress;
                                    size_t RHighPC = Ranges[I].dwr_addr2 + SelectedAddress;
                                    
                                    u32 RIndex = CompUnit->RangesCount++;
                                    CompUnit->RangesLowPCs[RIndex] = RLowPC;
                                    CompUnit->RangesHighPCs[RIndex] = RHighPC;
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
                            LOG_DWARF("CompUnit Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }

            Dwarf_Unsigned Version = 0;
            Dwarf_Small TableType = 0;
            Dwarf_Line_Context LineCtx = 0;
            DWARF_CALL(dwarf_srclines_b(DIE, &Version, &TableType, &LineCtx, Error));

            Dwarf_Signed BaseIdx = 0;
            Dwarf_Signed Count = 0;
            Dwarf_Signed EndIdx = 0;
            DWARF_CALL(dwarf_srclines_files_indexes(LineCtx, &BaseIdx, &Count, &EndIdx, Error));

            const char *CompileDir = 0x0;
            DWARF_CALL(dwarf_srclines_comp_dir(LineCtx, &CompileDir, Error));

            di_exec_src_file_bucket *Bucket = ArrayPush(&DI->Arena, di_exec_src_file_bucket, 1);
            Bucket->Files = ArrayPush(&DI->Arena, di_exec_src_file, Count);
            Bucket->CU = CompUnit;

            for(i64 I = BaseIdx; I < EndIdx; I++)
            {
                const char *FName = 0x0;
                Dwarf_Unsigned DirIdx = 0x0;
                DWARF_CALL(dwarf_srclines_files_data_b(LineCtx, I, &FName, &DirIdx, 0x0, 0x0, 0x0, Error));

                // NOTE(mateusz): We want to skip this "file" that appears as "<built-in>".
                char *BuiltInStr = "<built-in>";
                if(!StringMatches((char *)FName, BuiltInStr))
                {
                    const char *DName = 0x0;
                    i32 DirRes = dwarf_srclines_include_dir_data(LineCtx, DirIdx, &DName, Error);

                    if(DName == 0x0) { assert(DirRes != DW_DLV_OK); };

                    di_exec_src_file File = {};
                    
                    if(DName)
                    {
                        if(DName[0] == '/')
                        {
                            File.Dir = StringDuplicate(&DI->Arena, (char *)DName);
                        }
                        else
                        {
                            u32 Len1 = StringLength((char *)CompileDir);
                            u32 Len2 = StringLength((char *)DName);
                            char *DirWithComp = (char *)malloc(Len1 + Len2 + 16);

                            sprintf(DirWithComp, "%s/%s", CompileDir, DName);
                            File.Dir = StringDuplicate(&DI->Arena, DirWithComp);
                            free(DirWithComp);
                        }
                    }
                    else
                    {
                        File.Dir = StringDuplicate(&DI->Arena, (char *)CompileDir);
                    }
                    
                    File.Flags.ShowToUser = !StringStartsWith(File.Dir, "/usr/");
                    File.Name = StringDuplicate(&DI->Arena, (char *)FName);
                    File.DwarfIndex = I;
                    Bucket->Files[Bucket->Count++] = File;
                }
            }

            LOG_DWARF("Pushing a bucket with %u entries\n", Bucket->Count);
            SLL_QUEUE_PUSH(DI->ExecSrcFileList.Head, DI->ExecSrcFileList.Tail, Bucket);
            
            if(CompUnit->RangesCount >= 1)
            {
                assert(CompUnit->RangesLowPCs && CompUnit->RangesHighPCs);
            }

            // NOTE(mateusz): We read offsets, now add to them the load address so they represent the
            // the actual address inside the running excutable.
            if(Debugee.Flags.PIE)
            {
                for(u32 I = 0; I < CompUnit->RangesCount; I++)
                {
                    assert(Debugee.LoadAddress != 0x0);
                    CompUnit->RangesLowPCs[I] += Debugee.LoadAddress;
                    CompUnit->RangesHighPCs[I] += Debugee.LoadAddress;
                }
            }
        }break;
        case DW_TAG_subprogram:
        {
            LOG_DWARF("Subprogram\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_function *Func = &DI->Functions[DI->FunctionsCount++];
            assert(Func->LexScopesCount == 0);
            di_lexical_scope *LexScope = &Func->FuncLexScope;

            di_compile_unit *CompUnit = &DI->CompileUnits[DI->CompileUnitsCount - 1];
            if(!CompUnit->Functions)
            {
                CompUnit->Functions = Func;
            }

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
                        Func->Name = ArrayPush(&DI->Arena, char, Size);
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
                            
                            LOG_DWARF("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                            
                            if(AtomOut != DW_OP_call_frame_cfa)
                            {
                                const char *OpName = 0x0;
                                dwarf_get_OP_name(AtomOut, &OpName);

                                LOG_DWARF("AtomOut is = %d, %s\n", AtomOut, OpName);
                                assert(!"Call frame is not CFA");
                            }
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
                            AttrTag == DW_AT_sibling ||
                            AttrTag == DW_AT_noreturn;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            LOG_DWARF("Func Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }

            if(Debugee.Flags.PIE)
            {
                Func->FuncLexScope.LowPC += Debugee.LoadAddress;
                Func->FuncLexScope.HighPC += Debugee.LoadAddress;
            }
        }break;
        case DW_TAG_lexical_block:
        {
            LOG_DWARF("libdwarf: Lexical block\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            //DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            if(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error) != DW_DLV_OK)
                break;
            
            assert(DI->FunctionsCount);
            
            di_lexical_scope *LexScope = &DI->LexScopes[DI->LexScopesCount++];
            di_function *Func = &DI->Functions[DI->FunctionsCount - 1];
            if(!Func->LexScopes)
            {
                Func->LexScopes = LexScope;
            }
            
            Func->LexScopesCount += 1;
            
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
                        
                        LexScope->RangesLowPCs = ArrayPush(&DI->Arena, size_t, RangesCount);
                        LexScope->RangesHighPCs = ArrayPush(&DI->Arena, size_t, RangesCount);
                        
                        di_compile_unit *CU = &DI->CompileUnits[DI->CompileUnitsCount - 1];
                        size_t SelectedAddress = 0x0;
                        for(u32 I = 0; I < RangesCount; I++)
                        {
                            switch(Ranges[I].dwr_type)
                            {
                                case DW_RANGES_ENTRY:
                                {
                                    assert(CU->RangesCount >= 1);
                                    size_t RLowPC = CU->RangesLowPCs[0] + Ranges[I].dwr_addr1 + SelectedAddress;
                                    size_t RHighPC = CU->RangesLowPCs[0] + Ranges[I].dwr_addr2 + SelectedAddress;
                                    
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
                            AttrTag == DW_AT_decl_column ||
                            AttrTag == DW_AT_sibling;
                        
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            LOG_DWARF("Lexical Scope Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }

            if(Debugee.Flags.PIE)
            {
                LexScope->LowPC += Debugee.LoadAddress;
                LexScope->HighPC += Debugee.LoadAddress;
            }
        }break;
        case DW_TAG_variable:
        {
            LOG_DWARF("libdwarf: Variable\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_variable *Var = &DI->Variables[DI->VariablesCount++];

            di_compile_unit *CompUnit = &DI->CompileUnits[DI->CompileUnitsCount - 1];
            bool GlobalVariable = DI->DIEIndentLevel == 1;

            if(GlobalVariable)
            {
                if(!CompUnit->GlobalVariables)
                {
                    CompUnit->GlobalVariables = Var;
                }
                
                CompUnit->GlobalVariablesCount++;
            }
            else
            {
                if(CompUnit->Functions)
                {
                    di_function *Func = &DI->Functions[DI->FunctionsCount - 1];
                    bool HasLexScopes = Func->LexScopesCount != 0;
                    di_lexical_scope *LexScope = HasLexScopes ? &Func->LexScopes[Func->LexScopesCount - 1] : &Func->FuncLexScope;
                    if(!LexScope->Variables)
                    {
                        LexScope->Variables = Var;
                    }

                    LexScope->VariablesCount += 1;
                }
            }

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
                            Var->Name = ArrayPush(&DI->Arena, char, Size);
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

                                LOG_DWARF("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);

                                Var->LocationAtom = AtomOut;
                                Var->Offset = Operand1;
                            }
                        }break;
                    default:
                        {
                            bool ignored = AttrTag == DW_AT_decl_file ||
                                AttrTag == DW_AT_decl_line ||
                                AttrTag == DW_AT_decl_column ||
                                AttrTag == DW_AT_sibling ||
                                AttrTag == DW_AT_artificial ||
                                AttrTag == DW_AT_specification;

                            if(!ignored)
                            {
                                const char *AttrName = 0x0;
                                DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                                LOG_DWARF("Variable Unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                }
            }
        }break;
        case DW_TAG_formal_parameter:
        {
            // NOTE(mateusz): This is copy pasta from the variable code higher up
            LOG_DWARF("Variable\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            if(DI->FunctionsCount)
            {
                di_function *Func = &DI->Functions[DI->FunctionsCount - 1];
                if(Func->ParamCount == 0)
                {
                    Func->Params = &DI->Params[DI->ParamsCount];
                }
                Func->ParamCount += 1;
                di_variable *Param = &DI->Params[DI->ParamsCount++];
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
                            Param->Name = ArrayPush(&DI->Arena, char, Size);
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
                                
                                LOG_DWARF("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                                
                                Param->LocationAtom = AtomOut;
                                Param->Offset = Operand1;
                            }
                        }break;
                        default:
                        {
                            bool ignored = AttrTag == DW_AT_decl_file ||
                                AttrTag == DW_AT_decl_line ||
                                AttrTag == DW_AT_decl_column ||
                                AttrTag == DW_AT_sibling ||
                                AttrTag == DW_AT_specification;
                            
                            if(!ignored)
                            {
                                const char *AttrName = 0x0;
                                DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                                LOG_DWARF("Formal Parameter Unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_base_type:
        {
            LOG_DWARF("libdwarf: Base Type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_base_type *Type = (di_base_type *)&DI->BaseTypes[DI->BaseTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            Type->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            
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
                        Type->Name = ArrayPush(&DI->Arena, char, Size);
                        StringCopy(Type->Name, Name);
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
                        LOG_DWARF("Base Type Unhandled Attribute: %s\n", AttrName);
                    }break;
                }
            }
        }break;
        case DW_TAG_typedef:
        {
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_typedef *Typedef = &DI->Typedefs[DI->TypedefsCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            Typedef->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            
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
                        Typedef->Name = ArrayPush(&DI->Arena, char, Size);
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
                            LOG_DWARF("Base Type Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_pointer_type:
        {
            LOG_DWARF("libdwarf: Pointer Type\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_pointer_type *PType = &DI->PointerTypes[DI->PointerTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            PType->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            
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
                        //assert(!"Not expected TAG!");
                    }break;
                }
            }
            
        }break;
        case DW_TAG_const_type:
        {
            LOG_DWARF("libdwarf: Const Type\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            // NOTE(mateusz): Some DW_TAG_const_type are empty
            if(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error) == DW_DLV_OK)
            {
                di_const_type *CType = &DI->ConstTypes[DI->ConstTypesCount++];
                Dwarf_Off DIEOffset = 0;
                DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
                CType->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
                
                for(u32 I = 0; I < AttrCount; I++)
                {
                    Dwarf_Attribute Attribute = AttrList[I];
                    Dwarf_Half AttrTag = 0;
                    DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                    switch(AttrTag)
                    {
                        case DW_AT_type:
                        {
                            Dwarf_Off Offset = 0;
                            DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                            
                            CType->ActualTypeOffset = Offset;
                        }break;
                        default:
                        {
                            //assert(!"Not expected TAG!");
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_restrict_type:
        {
            LOG_DWARF("libdwarf: Restrict Type\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_restrict_type *RType = &DI->RestrictTypes[DI->RestrictTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            RType->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                switch(AttrTag)
                {
                    case DW_AT_type:
                    {
                        Dwarf_Off Offset = 0;
                        DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                        
                        RType->ActualTypeOffset = Offset;
                    }break;
                    default:
                    {
                        assert(!"Not expected TAG!");
                    }break;
                }
            }
            
        }break;
        case DW_TAG_structure_type:
        {
            LOG_DWARF("libdwarf: Strcture Type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_struct_type *StructType = &DI->StructTypes[DI->StructTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            StructType->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            
            /*
            This is to support things like this
            < 1><0x00009c75>    DW_TAG_union_type
                                  DW_AT_name                  Vec3
                                  DW_AT_byte_size             0x0000000c
                                  DW_AT_decl_file             0x00000001 /home/mateusz/src/cpp/hamster/src/hamster_math.h
                                  DW_AT_decl_line             0x00000040
                                  DW_AT_decl_column           0x00000007
                                  DW_AT_sibling               <0x00009d35>
            < 2><0x00009c82>      DW_TAG_structure_type
                                    DW_AT_byte_size             0x0000000c
                                    DW_AT_decl_file             0x00000001 /home/mateusz/src/cpp/hamster/src/hamster_math.h
                                    DW_AT_decl_line             0x00000043
                                    DW_AT_decl_column           0x00000002
                                    DW_AT_sibling               <0x00009cad>
            < 3><0x00009c8b>        DW_TAG_member
                                      DW_AT_name                  x
                                      DW_AT_decl_file             0x00000001 /home/mateusz/src/cpp/hamster/src/hamster_math.h
                                      DW_AT_decl_line             0x00000044
                                      DW_AT_decl_column           0x00000007
                                      DW_AT_type                  <0x000096d6>
                                      DW_AT_data_member_location  0
            < 3><0x00009c96>        DW_TAG_member
                                      DW_AT_name                  y
                                      DW_AT_decl_file             0x00000001 /home/mateusz/src/cpp/hamster/src/hamster_math.h
                                      DW_AT_decl_line             0x00000045
                                      DW_AT_decl_column           0x00000007
                                      DW_AT_type                  <0x000096d6>
                                      DW_AT_data_member_location  4
            < 3><0x00009ca1>        DW_TAG_member
                                      DW_AT_name                  z
                                      DW_AT_decl_file             0x00000001 /home/mateusz/src/cpp/hamster/src/hamster_math.h
                                      DW_AT_decl_line             0x00000046
                                      DW_AT_decl_column           0x00000007
                                      DW_AT_type                  <0x000096d6>
                                      DW_AT_data_member_location  8

            When there are structure types emplaced in the union instead of a member and a offset to it.
            */
            if(DI->WasUnion && DI->DIEIndentLevel == DI->LastUnionIndent + 1)
            {
                // There is a possibility of there not being enough space for the member given the fact we don't count it
                // when we are doing a pass over all the DIEs
                di_union_member *Member = &DI->UnionMembers[DI->UnionMembersCount++];

                di_union_type *Union = &DI->UnionTypes[DI->UnionTypesCount - 1];
                if(Union->MembersCount == 0)
                {
                    Union->Members = Member;
                }
                
                Union->MembersCount += 1;
                Member->ByteLocation = 0;
                Member->Name = "";
                Member->ActualTypeOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            }

            DI->WasUnion = false;
            DI->WasStruct = true;
            
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
                        StructType->Name = ArrayPush(&DI->Arena, char, Size);
                        StringCopy(StructType->Name, Name);
                    }break;
                    case DW_AT_byte_size:
                    {
                        Dwarf_Unsigned ByteSize = 0;
                        DWARF_CALL(dwarf_formudata(Attribute, &ByteSize, Error));
                        
                        StructType->ByteSize = ByteSize;
                    }break;
                    case DW_AT_declaration:
                    {
                        // TODO(mateusz): I have not way to really represent that in a way that is formal
                        // I have to create a test program for that and see how it behaves
                        StructType->Members = 0x0;
                        StructType->MembersCount = 0;
                    }break;
                    default:
                    {
                        bool ignored = AttrTag == DW_AT_decl_file ||
                            AttrTag == DW_AT_decl_line ||
                            AttrTag == DW_AT_decl_column ||
                            AttrTag == DW_AT_sibling;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            LOG_DWARF("Structure type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_union_type:
        {
            DI->LastUnionIndent = DI->DIEIndentLevel;
            LOG_DWARF("libdwarf: Union Type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_union_type *UnionType = &DI->UnionTypes[DI->UnionTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            UnionType->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            UnionType->Name = "";
            
            DI->WasUnion = true;
            DI->WasStruct = false;
            
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
                        UnionType->Name = ArrayPush(&DI->Arena, char, Size);
                        StringCopy(UnionType->Name, Name);
                    }break;
                    case DW_AT_byte_size:
                    {
                        Dwarf_Unsigned ByteSize = 0;
                        DWARF_CALL(dwarf_formudata(Attribute, &ByteSize, Error));
                        
                        UnionType->ByteSize = ByteSize;
                    }break;
                    case DW_AT_declaration:
                    {
                        // TODO(mateusz): I have not way to really represent that in a way that is formal
                        // I have to create a test program for that and see how it behaves
                        UnionType->Members = 0x0;
                        UnionType->MembersCount = 0;
                    }break;
                    default:
                    {
                        bool ignored = AttrTag == DW_AT_decl_file ||
                            AttrTag == DW_AT_decl_line ||
                            AttrTag == DW_AT_decl_column ||
                            AttrTag == DW_AT_sibling;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            LOG_DWARF("Union type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_member:
        {
            LOG_DWARF("libdwarf: Strcture/Union member\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            if(!DI->WasStruct && !DI->WasUnion)
            {
                LOG_DWARF("Unhandled class type\n");
                return;
            }
            
            if(DI->WasStruct)
            {
                di_struct_member *Member = &DI->StructMembers[DI->StructMembersCount++];
                
                di_struct_type *Struct = &DI->StructTypes[DI->StructTypesCount - 1];
                if(Struct->MembersCount == 0)
                {
                    Struct->Members = Member;
                }
                
                Struct->MembersCount += 1;
                Member->Name = "";
                
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
                            Member->Name = ArrayPush(&DI->Arena, char, Size);
                            StringCopy(Member->Name, Name);
                        }break;
                        case DW_AT_type:
                        {
                            Dwarf_Off Offset = 0;
                            DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                            
                            Member->ActualTypeOffset = Offset;
                        }break;
                        case DW_AT_data_member_location:
                        {
                            Dwarf_Unsigned Location = 0;
                            DWARF_CALL(dwarf_formudata(Attribute, &Location, Error));
                            
                            Member->ByteLocation = Location;
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
                                LOG_DWARF("Structure member unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
            else if(DI->WasUnion)
            {
                di_union_member *Member = &DI->UnionMembers[DI->UnionMembersCount++];
                
                di_union_type *Union = &DI->UnionTypes[DI->UnionTypesCount - 1];
                if(Union->MembersCount == 0)
                {
                    Union->Members = Member;
                }
                
                Union->MembersCount += 1;
                Member->ByteLocation = 0;
                Member->Name = "";
                
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
                            Member->Name = ArrayPush(&DI->Arena, char, Size);
                            StringCopy(Member->Name, Name);
                        }break;
                        case DW_AT_type:
                        {
                            Dwarf_Off Offset = 0;
                            DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                            
                            Member->ActualTypeOffset = Offset;
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
                                LOG_DWARF("Unionure member unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_array_type:
        {
            LOG_DWARF("libdwarf: Array type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_array_type *AType = &DI->ArrayTypes[DI->ArrayTypesCount++];
            
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            AType->DIEOffset = DIEOffset + DI->CompileUnits[DI->CompileUnitsCount - 1].Offset;
            
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                switch(AttrTag)
                {
                    case DW_AT_type:
                    {
                        Dwarf_Off Offset = 0;
                        DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                        
                        AType->ActualTypeOffset = Offset;
                    }break;
                    default:
                    {
                        bool ignored = AttrTag == DW_AT_sibling;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            LOG_DWARF("Array type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_subrange_type:
        {
            LOG_DWARF("libdwarf: Subrange type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            if(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error) != DW_DLV_OK)
                break;
            
            assert(DI->ArrayTypesCount);
            di_array_type *AType = &DI->ArrayTypes[DI->ArrayTypesCount - 1];
            
            for(u32 I = 0; I < AttrCount; I++)
            {
                Dwarf_Attribute Attribute = AttrList[I];
                Dwarf_Half AttrTag = 0;
                DWARF_CALL(dwarf_whatattr(Attribute, &AttrTag, Error));
                switch(AttrTag)
                {
                    case DW_AT_type:
                    {
                        Dwarf_Off Offset = 0;
                        DWARF_CALL(dwarf_dietype_offset(CurrentDIE, &Offset, Error));
                        
                        AType->RangesTypeOffset = Offset;
                    }break;
                    case DW_AT_upper_bound:
                    {
                        Dwarf_Unsigned Bound = 0;
                        DWARF_CALL(dwarf_formudata(Attribute, &Bound, Error));
                        
                        AType->UpperBound = Bound;
                    }break;
                    default:
                    {
                        bool ignored = false;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            LOG_DWARF("Array type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        default:
        {
            const char *TagName = 0x0;
            DWARF_CALL(dwarf_get_TAG_name(Tag, &TagName));
            LOG_DWARF("Unhandled Tag: %s\n", TagName);
        }break;
    }
}

static void
DwarfReadDIEMany(Dwarf_Debug Debug, Dwarf_Die DIE)
{
    Dwarf_Error Error_ = {};
    Dwarf_Error *Error = &Error_;
    Dwarf_Die CurrentDIE = DIE;

    DwarfReadDIE(Debug, CurrentDIE);
    
    Dwarf_Die ChildDIE = 0;
    i32 Result = dwarf_child(CurrentDIE, &ChildDIE, Error);
    
    if(Result == DW_DLV_OK)
    { 
        DI->DIEIndentLevel++;
        DwarfReadDIEMany(Debug, ChildDIE);
        Dwarf_Die SiblingDIE = ChildDIE;
        
        while(Result == DW_DLV_OK)
        {
            CurrentDIE = SiblingDIE;
            Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, Error);
            if(Result == DW_DLV_OK)
            {
                DwarfReadDIEMany(Debug, SiblingDIE);
            }
            else
            {
                break;
            }
        };
        DI->DIEIndentLevel--;
    }
    
    return;
}

static void
DwarfCountTags(Dwarf_Debug Debug, Dwarf_Die DIE, u32 CountTable[DWARF_TAGS_COUNT])
{
    Dwarf_Error Error_ = {};
    Dwarf_Error *Error = &Error_;
    Dwarf_Die CurrentDIE = DIE;
    
    Dwarf_Half Tag = 0;
    assert(dwarf_tag(CurrentDIE, &Tag, Error) == DW_DLV_OK);
    
    assert(Tag <= DWARF_TAGS_COUNT);
    CountTable[Tag] += 1;
    
    Dwarf_Die ChildDIE = 0;
    i32 Result = dwarf_child(CurrentDIE, &ChildDIE, Error);
    
    if(Result == DW_DLV_OK)
    { 
        DwarfCountTags(Debug, ChildDIE, CountTable);
        Dwarf_Die SiblingDIE = ChildDIE;
        while(Result == DW_DLV_OK)
        {
            CurrentDIE = SiblingDIE;
            Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, Error);
            if(Result == DW_DLV_OK)
            {
                DwarfCountTags(Debug, SiblingDIE, CountTable);
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
DwarfRead()
{
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    Dwarf_Error *Error = 0x0;
    
    DwarfOpenSymbolsHandle(&DI->DwarfFd, &DI->Debug);
    
    u32 *CountTable = (u32 *)calloc(DWARF_TAGS_COUNT, sizeof(u32));
    DI->Arena = ArenaCreateZeros(Kilobytes(64));
    
    for(i32 CUCount = 0;;++CUCount)
    {
        i32 Result = dwarf_next_cu_header(DI->Debug, &CUHeaderLength,
                                          &Version, &AbbrevOffset, &AddressSize,
                                          &NextCUHeader, Error);
        
        assert(Result != DW_DLV_ERROR);
        if(Result  == DW_DLV_NO_ENTRY) {
            break;
        }
        
        /* The CU will have a single sibling, a cu_die. */
        Dwarf_Die CurrentDIE = 0;
        Result = dwarf_siblingof(DI->Debug, 0, &CurrentDIE, Error);
        assert(Result != DW_DLV_ERROR && Result != DW_DLV_NO_ENTRY);
        
        DwarfCountTags(DI->Debug, CurrentDIE, CountTable);
    }
    
    //TIMER_START(0);
    
    DI->CompileUnits = ArrayPush(&DI->Arena, di_compile_unit, CountTable[DW_TAG_compile_unit]);
    DI->Functions = ArrayPush(&DI->Arena, di_function, CountTable[DW_TAG_subprogram]);
    DI->BaseTypes = ArrayPush(&DI->Arena, di_base_type, CountTable[DW_TAG_base_type]);
    DI->Typedefs = ArrayPush(&DI->Arena, di_typedef, CountTable[DW_TAG_typedef]);
    DI->PointerTypes = ArrayPush(&DI->Arena, di_pointer_type, CountTable[DW_TAG_pointer_type]);
    DI->ConstTypes = ArrayPush(&DI->Arena, di_const_type, CountTable[DW_TAG_const_type]);
    DI->RestrictTypes = ArrayPush(&DI->Arena, di_restrict_type, CountTable[DW_TAG_restrict_type]);
    DI->Variables = ArrayPush(&DI->Arena, di_variable, CountTable[DW_TAG_variable]);
    DI->Params = ArrayPush(&DI->Arena, di_variable, CountTable[DW_TAG_formal_parameter]);
    DI->LexScopes = ArrayPush(&DI->Arena, di_lexical_scope, CountTable[DW_TAG_lexical_block]);
    DI->StructMembers = ArrayPush(&DI->Arena, di_struct_member, CountTable[DW_TAG_member]);
    DI->StructTypes = ArrayPush(&DI->Arena, di_struct_type, CountTable[DW_TAG_structure_type]);
    DI->UnionMembers = ArrayPush(&DI->Arena, di_union_member, CountTable[DW_TAG_member]);
    DI->UnionTypes = ArrayPush(&DI->Arena, di_union_type, CountTable[DW_TAG_union_type]);
    DI->ArrayTypes = ArrayPush(&DI->Arena, di_array_type, CountTable[DW_TAG_array_type]);
    DI->SourceFiles = ArrayPush(&DI->Arena, di_src_file, MAX_DI_SOURCE_FILES);


    for(u32 I = 0; I < DWARF_TAGS_COUNT; I++)
    {
        if(CountTable[I])
        {
            const char *A = 0x0;
            dwarf_get_TAG_name(I, &A);
            LOG_DWARF("[%s]: %d\n", A, CountTable[I]);
        }
    }

    
    //TIMER_END(0);
    
    for(i32 CUCount = 0;;++CUCount)
    {
        // NOTE(mateusz): I don't know what it does
        i32 Result = dwarf_next_cu_header(DI->Debug, &CUHeaderLength,
                                          &Version, &AbbrevOffset, &AddressSize,
                                          &NextCUHeader, Error);

        assert(Result != DW_DLV_ERROR);
        if(Result  == DW_DLV_NO_ENTRY) {
            break;
        }
        
        /* The CU will have a single sibling, a cu_die. */
        Dwarf_Die CurrentDIE = 0;
        Result = dwarf_siblingof(DI->Debug, 0, &CurrentDIE, Error);
        assert(Result != DW_DLV_ERROR && Result != DW_DLV_NO_ENTRY);
        
        DwarfReadDIEMany(DI->Debug, CurrentDIE);
    }
    
    DwarfCloseSymbolsHandle(&DI->DwarfFd, &DI->Debug);
    
    // NOTE(mateusz): This time without finish to preserve it
    DwarfOpenSymbolsHandle(&DI->CFAFd, &DI->CFADebug);
    
    Dwarf_Cie *CIEs;
    Dwarf_Signed CIECount;
    Dwarf_Fde *FDEs;
    Dwarf_Signed FDECount;
    DWARF_CALL(dwarf_get_fde_list_eh(DI->CFADebug, &CIEs, &CIECount, &FDEs, &FDECount, Error));
    
    di_frame_info *Frame = &DI->FrameInfo;
    Frame->CIECount = CIECount;
    Frame->FDECount = FDECount;
    Frame->CIEs = CIEs;
    Frame->FDEs = FDEs;
    
    free(CountTable);
}

static bool
DwarfEvalFDE(size_t Address, u32 RegsTableSize, Dwarf_Regtable3 *Result, address_range *InRange)
{
    bool Success = false;
    Address = Debugee.Flags.PIE ? Address - Debugee.LoadAddress : Address;
    di_frame_info *Frame = &DI->FrameInfo;
    for(u32 J = 0; J < Frame->FDECount; J++)
    {
        Dwarf_Error *Error  = 0;
        Dwarf_Addr FDELowPC = 0;
        Dwarf_Unsigned FDEFunctionLength = 0;
        DWARF_CALL(dwarf_get_fde_range(Frame->FDEs[J], &FDELowPC, &FDEFunctionLength,
                                       0x0, 0x0, 0x0, 0x0, 0x0, Error));
        
        if(AddressBetween(Address, FDELowPC, FDELowPC + FDEFunctionLength - 1))
        {
			if(InRange)
			{
				InRange->Start = FDELowPC;
				InRange->End = FDELowPC + FDEFunctionLength - 1;
			}
			
            if(RegsTableSize)
            {
                Result->rt3_reg_table_size = RegsTableSize;
                Result->rt3_rules = (Dwarf_Regtable_Entry3_s *)malloc(sizeof(Result->rt3_rules[0]) * RegsTableSize);
            }
            
            Dwarf_Addr ActualPC = 0;
            DWARF_CALL(dwarf_get_fde_info_for_all_regs3(Frame->FDEs[J], Address, Result, &ActualPC, Error));

            Success = true;
            break;
        }
    }

    return Success;
}

static size_t
DwarfCalculateCFA(Dwarf_Regtable3 *Table, x64_registers Registers)
{
    Dwarf_Small OffsetRel = Table->rt3_cfa_rule.dw_offset_relevant;
    Dwarf_Signed OffsetOut = Table->rt3_cfa_rule.dw_offset_or_block_len;
    Dwarf_Half RegnumOut = Table->rt3_cfa_rule.dw_regnum;

    assert(OffsetRel == 1 && Table->rt3_cfa_rule.dw_offset_relevant != 0);
    LOG_DWARF("CFA by reg num = %d\n", RegnumOut);
    size_t RegVal = RegisterGetByABINumber(Registers, RegnumOut);
            
    LOG_DWARF("RegVal = %lX, OffsetOut = %llX, RegVal + OffsetOut = %lX\n", RegVal, OffsetOut, (size_t)((ssize_t)RegVal + (ssize_t)OffsetOut));

    size_t CFA = RegVal + OffsetOut;

    return CFA;
}
    
static size_t
DwarfGetCanonicalFrameAddress(size_t Address)
{
    size_t Result = 0x0;

    if(AddressBetween(Address, DI->CFAAddrRange))
    {
		Result = DI->CachedCFA;
    }
    else
    {
        Dwarf_Regtable3 Table = {};
        assert(DwarfEvalFDE(Address, 0, &Table, &DI->CFAAddrRange));

        Result = DwarfCalculateCFA(&Table, Debugee.Regs);
        DI->CachedCFA = Result;
    }

    return Result;
}

static bool
DwarfAddressInFrame(size_t Address)
{
    bool Result = false;

    Dwarf_Regtable3 Table = {};
    Result = DwarfEvalFDE(Address, 0, &Table, 0x0);

    return Result;
}

static di_variable *
DwarfGetFunctionsFirstVariable(di_function *Func)
{
    di_variable *Result = 0x0;

    if(Func->FuncLexScope.VariablesCount > 0)
    {
        Result = Func->FuncLexScope.Variables;
    }
    else
    {
        for(u32 I = 0; I < Func->LexScopesCount; I++)
        {
            if(Func->LexScopes[I].VariablesCount > 0)
            {
                Result = Func->LexScopes[I].Variables;
                break;
            }
        }
    }

    return Result;
}

static char *
DwarfGetFunctionStringRepresentation(di_function *Func, arena *Arena)
{
    char *Result = 0x0;

    di_underlaying_type FuncReturnType = DwarfFindUnderlayingType(Func->TypeOffset);
    
    char *TypeName = DwarfGetTypeStringRepresentation(FuncReturnType, Arena);
    char *FuncName = (char *)(Func->Name ? Func->Name : "EMPTY_FUNC_NAME");

    u32 TypeLen = StringLength(TypeName);
    u32 NameLen = StringLength(FuncName);
    u32 ParamsLen = 0;

    scratch_arena Scratch;
    char **ParamsTypes = ArrayPush(Scratch, char *, Func->ParamCount);
    for(u32 I = 0; I < Func->ParamCount; I++)
    {
        di_underlaying_type ParamType = DwarfFindUnderlayingType(Func->Params[I].TypeOffset);
        ParamsTypes[I] = DwarfGetTypeStringRepresentation(ParamType, &Gui->Arena);
        
        ParamsLen += StringLength(ParamsTypes[I]);
    }

    Result = ArrayPush(Arena, char, TypeLen + NameLen + ParamsLen + Func->ParamCount * 3 + 128);
    char *WriteHead = Result;

    const char *MainFmtStr = Func->ParamCount ? "%s %s(" : "%s %s()";
    WriteHead += sprintf(WriteHead, MainFmtStr, TypeName, FuncName);
    for(u32 I = 0; I < Func->ParamCount; I++)
    {
        const char *ParamFmtStr = I == Func->ParamCount - 1 ? "%s)" : "%s, ";
        WriteHead += sprintf(WriteHead, ParamFmtStr, ParamsTypes[I]);
    }
    
    return Result;
}

static bool
DwarfIsAddressInDifferentSourceLine(size_t Address)
{
    di_src_line *Current = DwarfFindLineByAddress(DebugeeGetProgramCounter(&Debugee));
    di_src_line *Diff = DwarfFindLineByAddress(Address);
    assert(Current);
    assert(Diff);

    LOG_DWARF("LineNum: Current = %u, Diff = %u / Address: Current = %lx, Diff = %lx\n", Current->LineNum, Diff->LineNum, Current->Address, Diff->Address);

    bool SameLineDiffFiles = (Current->LineNum == Diff->LineNum) && (Current->SrcFileIndex != Diff->SrcFileIndex);
    bool SameFileDiffLines = (Current->LineNum != Diff->LineNum) && (Current->Address != Diff->Address);
    if(SameLineDiffFiles || SameFileDiffLines)
    {
        assert(Current != Diff);
        return true;
    }
        
    return false;
}

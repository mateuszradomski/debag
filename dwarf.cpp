
debug_info *DI = 0x0;

static bool
OpenDwarfSymbolsHandle()
{
    DI->DwarfFd = open(Debuger.DebugeeProgramPath, O_RDONLY);
    assert(DI->DwarfFd != -1);
    
    bool Result = dwarf_init(DI->DwarfFd, DW_DLC_READ, 0, 0, &DI->Debug, 0x0) == DW_DLV_OK;
    
    return Result;
}

static void
CloseDwarfSymbolsHandle()
{
    assert(dwarf_finish(DI->Debug, 0x0) == DW_DLV_OK);
    close(DI->DwarfFd);
}

static bool LoadSourceContaingAddress(size_t Address, u32 *FileIdxOut, u32 *LineIdxOut);

static di_src_line *
LineTableFindByAddress(size_t Address)
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
    bool Found = LoadSourceContaingAddress(Address, &FileIdx, &LineIdx);
    
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
LineFindByNumber(u32 LineNum, u32 SrcFileIndex)
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

static di_function *
FindFunctionConfiningAddress(size_t Address)
{
    di_function *Result = 0x0;
    
    for(u32 I = 0; I < DI->FuctionsCount; I++)
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

static di_underlaying_type
FindUnderlayingType(size_t BTDIEOffset)
{
    di_underlaying_type Result = {};
    
    for(u32 I = 0; I < DI->TypedefsCount; I++)
    {
        if(DI->Typedefs[I].DIEOffset == BTDIEOffset)
        {
            Result = FindUnderlayingType(DI->Typedefs[I].ActualTypeOffset);
            Result.Flags |= TYPE_IS_TYPEDEF;
            Result.Name = DI->Typedefs[I].Name;
            
            return Result;
        }
    }
    
    for(u32 I = 0; I < DI->PointerTypesCount; I++)
    {
        if(DI->PointerTypes[I].DIEOffset == BTDIEOffset)
        {
            Result = FindUnderlayingType(DI->PointerTypes[I].ActualTypeOffset);
            Result.Flags |= TYPE_IS_POINTER;
            Result.PointerCount += 1;
            return Result;
        }
    }
    
    for(u32 I = 0; I < DI->ConstTypesCount; I++)
    {
        if(DI->ConstTypes[I].DIEOffset == BTDIEOffset)
        {
            Result = FindUnderlayingType(DI->ConstTypes[I].ActualTypeOffset);
            Result.Flags |= TYPE_IS_CONST;
            return Result;
        }
    }
    
    for(u32 I = 0; I < DI->RestrictTypesCount; I++)
    {
        if(DI->RestrictTypes[I].DIEOffset == BTDIEOffset)
        {
            Result = FindUnderlayingType(DI->RestrictTypes[I].ActualTypeOffset);
            Result.Flags |= TYPE_IS_RESTRICT;
            return Result;
        }
    }
    
    for(u32 I = 0; I < DI->ArrayTypesCount; I++)
    {
        if(DI->ArrayTypes[I].DIEOffset == BTDIEOffset)
        {
            Result = FindUnderlayingType(DI->ArrayTypes[I].ActualTypeOffset);
            Result.ArrayUpperBound = DI->ArrayTypes[I].UpperBound;
            Result.Flags |= TYPE_IS_ARRAY;
            return Result;
        }
    }
    
    // Underlaying types
    for(u32 I = 0; I < DI->StructTypesCount; I++)
    {
        if(DI->StructTypes[I].DIEOffset == BTDIEOffset)
        {
            Result.Flags |= TYPE_IS_STRUCT;
            Result.Struct = &DI->StructTypes[I];
            Result.Name = DI->StructTypes[I].Name;
            
            return Result;
        }
    }
    
    for(u32 I = 0; I < DI->UnionTypesCount; I++)
    {
        if(DI->UnionTypes[I].DIEOffset == BTDIEOffset)
        {
            Result.Flags |= TYPE_IS_STRUCT;
            Result.Union = &DI->UnionTypes[I];
            Result.Name = DI->UnionTypes[I].Name;
            
            return Result;
        }
    }
    
    for(u32 I = 0; I < DI->BaseTypesCount; I++)
    {
        if(DI->BaseTypes[I].DIEOffset == BTDIEOffset)
        {
            Result.Flags |= TYPE_IS_BASE;
            Result.Type = &DI->BaseTypes[I];
            Result.Name = DI->BaseTypes[I].Name;
            
            return Result;
        }
    }
    
    return Result;
}

#if 0
static di_base_type *
FindBaseTypeByOffset(size_t BTDIEOffset)
{
    di_base_type *Type = 0x0;
    
    Type = FindBaseTypeByOffset(BTDIEOffset, 0x0);
    
    return Type;
}
#endif

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
                printf("Unsupported byte size = %d", Type->ByteSize);
                Result = "";
            }break;
        }
    }
    
    return Result;
}

#if 0
static char *
BaseTypeToFormatStr(size_t BTDIEOffset)
{
    type_flags TFlag = 0;
    di_base_type *Type = FindBaseTypeByOffset(BTDIEOffset, &TFlag);
    
    return BaseTypeToFormatStr(Type, TFlag);
}
#endif

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

static bool
AddressInCompileUnit(di_compile_unit *CU, size_t Address)
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

static bool
AddressInAnyCompileUnit(size_t Address)
{
    bool Result = false;

    for(u32 I = 0; I < DI->CompileUnitsCount; I++)
    {
        di_compile_unit *CU = &DI->CompileUnits[I];
        if(AddressInCompileUnit(CU, Address))
        {
            Result = true;
            break;
        }
    }

    return Result;
}

static di_src_file *
FindSourceFile(char *Path)
{
    di_src_file *Result = 0x0;
    
    for(u32 I = 0; I < DI->SourceFilesCount; I++)
    {
        if(StringsMatch(Path, DI->SourceFiles[I].Path))
        {
            Result = &DI->SourceFiles[I];
            break;
        }
    }
    
    return Result;
}

static di_src_file *
PushSourceFile(char *Path, u32 SrcLineCount)
{
    di_src_file *Result = 0x0;
    
    Result = &DI->SourceFiles[DI->SourceFilesCount++];
    
    Result->Path = StringDuplicate(DI->Arena, Path);
    Result->Content = DumpFile(DI->Arena, Path);
    Result->ContentLineCount = StringCountChar(Result->Content, '\n');
    Result->SrcLineCount = 0;
    Result->Lines = ArrayPush(DI->Arena, di_src_line, SrcLineCount);
    
    return Result;
}

static di_src_file *
PushSourceFile(char *Path)
{
    di_src_file *Result = 0x0;
    
    Result = &DI->SourceFiles[DI->SourceFilesCount++];
    
    Result->Path = StringDuplicate(DI->Arena, Path);
    Result->Content = DumpFile(DI->Arena, Path);
    Result->ContentLineCount = StringCountChar(Result->Content, '\n');
    
    return Result;
}

static u32
SrcFileAssociatePath(char *Path)
{
    u32 Result = MAX_DI_SOURCE_FILES + 1;
    
    assert(Path);
    for(u32 I = 0; I < DI->SourceFilesCount; I++)
    {
        if(StringsMatch(Path, DI->SourceFiles[I].Path))
        {
            Result = I;
            break;
        }
    }
    
    if(DI->SourceFilesCount == 0 || Result == MAX_DI_SOURCE_FILES + 1)
    {
        PushSourceFile(Path);
        Result = DI->SourceFilesCount - 1;
    }
    
    return Result;
}

static Dwarf_Die
FindDIEWithOffset(Dwarf_Debug Debug, Dwarf_Die DIE, size_t Offset)
{
    Dwarf_Off DIEOffset = 0;
    DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, 0x0));
    
    if(DIEOffset == Offset)
    {
        return DIE;
    }
    else
    {
        Dwarf_Die ChildDIE = 0;
        i32 Result = dwarf_child(DIE, &ChildDIE, 0x0);
        
        if(Result == DW_DLV_OK)
        { 
            return FindDIEWithOffset(Debug, ChildDIE, Offset);
            Dwarf_Die SiblingDIE = ChildDIE;
            while(Result == DW_DLV_OK)
            {
                DIE = SiblingDIE;
                Result = dwarf_siblingof(Debug, DIE, &SiblingDIE, 0x0);
                if(Result == DW_DLV_OK)
                {
                    return FindDIEWithOffset(Debug, SiblingDIE, Offset);
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
CountLinesInFileIndex(Dwarf_Line *Lines, u32 LineCount, u32 FileIdx)
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
DumpLinesMatchingIndex(Dwarf_Line *Lines, u32 LineCount, di_src_file *File, u32 FileIdx, u32 LineNum, u32 *LineIdxOut)
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

            if(LineNO == LineNum)
            {
                *LineIdxOut = File->SrcLineCount;
            }

            Line.Address = Addr;
            Line.LineNum = LineNO;

            Dwarf_Signed LineOffset = 0;
            DWARF_CALL(dwarf_lineoff(Lines[I], &LineOffset, 0x0));
            
            //printf("Pair Addr - LineNO => %llx - %llu, with offset = %llx\n", Addr, LineNO, LineOffset);

            File->Lines[File->SrcLineCount++] = Line;
        }
    }
}

static bool
LoadSourceContaingAddress(size_t Address, u32 *FileIdxOut, u32 *LineIdxOut)
{
    bool Result = false;
    
    assert(OpenDwarfSymbolsHandle());
    
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    Dwarf_Error *Error = 0x0;
    
    size_t CUDIEOffset = 0;
    if(DI->CompileUnitsCount > 0)
    {
        for(u32 I = 0; I < DI->CompileUnitsCount; I++)
        {
            di_compile_unit *CompUnit = &DI->CompileUnits[I];
            for(u32 RI = 0; RI < CompUnit->RangesCount; RI++)
            {
                //printf("%lx, %lx, Address = %lx\n", CompUnit->RangesLowPCs[RI], CompUnit->RangesHighPCs[RI], Address);
                ssize_t LowPC = CompUnit->RangesLowPCs[RI];
                ssize_t HighPC = CompUnit->RangesHighPCs[RI];
                //printf("compunit, LOWPC, HIGHPC = %lx, %lx, Address = %lx\n", LowPC, HighPC, Address);
                
                if(AddressBetween(Address, LowPC, HighPC))
                {
                    CUDIEOffset = CompUnit->DIEOffset;
                }
            }
        }
        
        if(CUDIEOffset)
        {
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
                
                SearchDie = FindDIEWithOffset(DI->Debug, CurrentDIE, CUDIEOffset);
                if(SearchDie)
                {
                    break;
                }
            }
            
            if(SearchDie)
            {
                Dwarf_Half Tag = 0;
                DWARF_CALL(dwarf_tag(SearchDie, &Tag, 0x0));
                assert(Tag == DW_TAG_compile_unit);
                
                Dwarf_Unsigned Version = 0;
                Dwarf_Small TableType = 0;
                Dwarf_Line_Context LineCtx = 0;
                DWARF_CALL(dwarf_srclines_b(SearchDie, &Version, &TableType, &LineCtx, 0x0));
                
                Dwarf_Signed SrcFilesCount = 0;
                dwarf_srclines_files_count(LineCtx, &SrcFilesCount, Error);
                DI->SourceFilesInExec += SrcFilesCount;
                
                //printf("There are %lld source files in this compilation unit\n", SrcFilesCount);
                
                Dwarf_Line *LineBuffer = 0;
                Dwarf_Signed LineCount = 0;
                DWARF_CALL(dwarf_srclines_from_linecontext(LineCtx, &LineBuffer, &LineCount, Error));
                
                //printf("There are %lld source lines\n", LineCount);
                for(i32 I = 0; I < LineCount; ++I)
                {
                    Dwarf_Addr LineAddr = 0;
                    Dwarf_Unsigned FileNum = 0;
                    Dwarf_Unsigned LineNum = 0;
                    
                    DWARF_CALL(dwarf_lineaddr(LineBuffer[I], &LineAddr, Error));
                    DWARF_CALL(dwarf_lineno(LineBuffer[I], &LineNum, Error));
                    DWARF_CALL(dwarf_line_srcfileno(LineBuffer[I], &FileNum, Error));
                    
                    if(Address == LineAddr)
                    {
                        // Dump this file into memory
                        //printf("Address = %lx, LineAddr = %llx, FileNum = %llu, LineNum = %llu\n", Address, LineAddr, FileNum, LineNum);

                        char *FileName = 0x0;
                        DWARF_CALL(dwarf_linesrc(LineBuffer[I], &FileName, Error));
                        printf("Address %lx, FileName %p [%s]\n", Address, (void *)FileName, FileName);
                        u32 LinesMatching = CountLinesInFileIndex(LineBuffer, LineCount, FileNum);

                        di_src_file *File = PushSourceFile(FileName, LinesMatching);
                        printf("Pushing source file %s\n", FileName);

                        DumpLinesMatchingIndex(LineBuffer, LineCount, File, FileNum, LineNum, LineIdxOut);

                        *FileIdxOut = DI->SourceFilesCount - 1;

                        Result = true;
                        return Result;
                    }
                }

                return Result;
            }
        }
    }
    
    CloseDwarfSymbolsHandle();
    
    return Result;
}

static address_range
AddressRangeCurrentAndNextLine(size_t StartAddress)
{
    address_range Result = {};
    
    di_src_line *Current = LineTableFindByAddress(StartAddress);
    if(!Current)
    {
        printf("Didn't find line with address = %lx\n", StartAddress);
        assert(false);
    }
    di_src_file *File = &DI->SourceFiles[Current->SrcFileIndex];
printf("Current->Address = %lx, Current->SrcFileIndex = %d\n", Current->Address, Current->SrcFileIndex);

    u32 LineIdx = Current - File->Lines;
    for(u32 I = LineIdx; I < File->SrcLineCount; I++)
    {
        if(File->SrcLineCount == I + 1)
        {
            di_function *Func = FindFunctionConfiningAddress(Current->Address);
            Result.Start = Current->Address;
            // TODO(mateusz): I think this will be different, in that it will use 
            // the lexical scopes
            Result.End = Func->FuncLexScope.HighPC;
            break;
        }
        else
        {
            di_src_line *Next = &File->Lines[I];
            if(Next->LineNum != Current->LineNum)
            {
                //printf("Next->LineNum = %d, Current->LineNum = %d\n",Next->LineNum, Current->LineNum);
                //printf("Next->Address = %lX, Current->Address = %lX\n",Next->Address, Current->Address);
                Result.Start = Current->Address;
                Result.End = Next->Address;

                break;
            }
        }
    }
    
    return Result;
}

static size_t
FindEntryPointAddress()
{
    size_t Result = 0;
    
    for(u32 I = 0; I < DI->FuctionsCount; I++)
    {
        if(StringsMatch(DI->Functions[I].Name, "main"))
        {
            printf("entrypoint: %s\n", DI->Functions[I].Name);
            Result = DI->Functions[I].FuncLexScope.LowPC;
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
    printf("Load Path is %s\n", Path);
    
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


// TODO(mateusz): The bigest hack of all time, fix this, record when Struct is read
// and when Union is read
bool WasStruct = false;
bool WasUnion = false;

#define LOG_UNHANDLED(...) do { } while (0)

static void
DWARFReadDIEs(Dwarf_Debug Debug, Dwarf_Die DIE)
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
            //LOG_UNHANDLED("libdwarf: Compile Unit\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_compile_unit *CompUnit = &DI->CompileUnits[DI->CompileUnitsCount++];
            
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            CompUnit->DIEOffset = DIEOffset;
            
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
                        CompUnit->Name = ArrayPush(DI->Arena, char, Size);
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
                            CompUnit->RangesLowPCs = ArrayPush(DI->Arena, size_t, 1);
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
                            CompUnit->RangesHighPCs = ArrayPush(DI->Arena, size_t, 1);
                            Dwarf_Addr *WritePoint = (Dwarf_Addr *)CompUnit->RangesHighPCs;
                            
                            Dwarf_Half Form = 0;
                            Dwarf_Form_Class FormType = {};
                            DWARF_CALL(dwarf_highpc_b(DIE, WritePoint, &Form, &FormType, 0x0));
                            if (FormType == DW_FORM_CLASS_CONSTANT) {
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
                        printf("ranges\n");
                        Dwarf_Off DebugRangesOffset = 0;
                        DWARF_CALL(dwarf_global_formref(Attribute, &DebugRangesOffset, Error));
                        
                        DWARF_CALL(dwarf_get_ranges_a(Debug, DebugRangesOffset, DIE, &Ranges,
                                                      &RangesCount, &ByteCount, Error));
                        
                        CompUnit->RangesLowPCs = ArrayPush(DI->Arena, size_t, RangesCount);
                        CompUnit->RangesHighPCs = ArrayPush(DI->Arena, size_t, RangesCount);
                        
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
                            LOG_UNHANDLED("CompUnit Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
            
            if(CompUnit->RangesCount >= 1)
            {
                assert(CompUnit->RangesLowPCs && CompUnit->RangesHighPCs);
            }
            
#if 0            
            Dwarf_Unsigned Version = 0;
            Dwarf_Small TableType = 0;
            Dwarf_Line_Context LineCtx = 0;
            DWARF_CALL(dwarf_srclines_b(DIE, &Version, &TableType, &LineCtx, Error));
            
            Dwarf_Signed SrcFilesCount = 0;
            dwarf_srclines_files_count(LineCtx, &SrcFilesCount, Error);
            DI->SourceFilesInExec += SrcFilesCount;
            
            printf("There are %lld source files in this compilation unit\n", SrcFilesCount);
            
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
                
                di_src_line *LTEntry = &DI->SourceLines[DI->SourceLinesCount++];
                LTEntry->Address = LineAddr;
                LTEntry->LineNum = LineNum;
                LTEntry->SrcFileIndex = SrcFileAssociatePath(LineSrcFile);
            }
#endif
        }break;
        case DW_TAG_subprogram:
        {
            //LOG_UNHANDLED("Subprogram\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_function *Func = &DI->Functions[DI->FuctionsCount++];
            assert(Func->LexScopesCount == 0);
            di_lexical_scope *LexScope = &Func->FuncLexScope;
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
                        Func->Name = ArrayPush(DI->Arena, char, Size);
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
                            
                            //LOG_UNHANDLED("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                            
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
                            AttrTag == DW_AT_sibling ||
                            AttrTag == DW_AT_noreturn;
                        if(!ignored)
                        {
                            const char *AttrName = 0x0;
                            DWARF_CALL(dwarf_get_AT_name(AttrTag, &AttrName));
                            LOG_UNHANDLED("Func Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_lexical_block:
        {
            //LOG_UNHANDLED("libdwarf: Lexical block\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            assert(DI->FuctionsCount);
            
            di_lexical_scope *LexScope = &DI->LexScopes[DI->LexScopesCount++];
            di_function *Func = &DI->Functions[DI->FuctionsCount - 1];
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
                        
                        LexScope->RangesLowPCs = ArrayPush(DI->Arena, size_t, RangesCount);
                        LexScope->RangesHighPCs = ArrayPush(DI->Arena, size_t, RangesCount);
                        
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
                            LOG_UNHANDLED("Lexical Scope Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_variable:
        {
            //LOG_UNHANDLED("libdwarf: Variable\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_variable *Var = &DI->Variables[DI->VariablesCount++];
            
            // NOTE(mateusz): Globals
            if(DI->FuctionsCount)
            {
                if(DI->FuctionsCount)
                {
                    
                    di_function *Func = &DI->Functions[DI->FuctionsCount - 1];
                    bool HasLexScopes = Func->LexScopesCount != 0;
                    di_lexical_scope *LexScope = HasLexScopes ? &Func->LexScopes[Func->LexScopesCount - 1] : &Func->FuncLexScope;
                    if(!LexScope->Variables)
                    {
                        LexScope->Variables = Var;
                    }
                    
                    LexScope->VariablesCount += 1;
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
                            Var->Name = ArrayPush(DI->Arena, char, Size);
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
                                
                                //LOG_UNHANDLED("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                                
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
                                LOG_UNHANDLED("Variable Unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_formal_parameter:
        {
            // NOTE(mateusz): This is copy pasta from the variable code higher up
            //LOG_UNHANDLED("Variable\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            // TODO(mateusz): Globals
            if(DI->FuctionsCount)
            {
                di_function *Func = &DI->Functions[DI->FuctionsCount - 1];
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
                            Param->Name = ArrayPush(DI->Arena, char, Size);
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
                                
                                //LOG_UNHANDLED("AtomOut = %d, Oper1 = %lld, Oper2 = %llu, Oper3 = %llu, OffsetBranch = %llu\n", AtomOut, Operand1, Operand2, Operand3, OffsetBranch);
                                
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
                                LOG_UNHANDLED("Formal Parameter Unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_base_type:
        {
            //LOG_UNHANDLED("libdwarf: Base Type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_base_type *Type = (di_base_type *)&DI->BaseTypes[DI->BaseTypesCount++];
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
                        char *Name = 0x0;
                        DWARF_CALL(dwarf_formstring(Attribute, &Name, Error));
                        
                        u32 Size = strlen(Name) + 1;
                        Type->Name = ArrayPush(DI->Arena, char, Size);
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
                        LOG_UNHANDLED("Base Type Unhandled Attribute: %s\n", AttrName);
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
                        Typedef->Name = ArrayPush(DI->Arena, char, Size);
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
                            LOG_UNHANDLED("Base Type Unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_pointer_type:
        {
            //LOG_UNHANDLED("libdwarf: Pointer Type\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_pointer_type *PType = &DI->PointerTypes[DI->PointerTypesCount++];
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
        case DW_TAG_const_type:
        {
            //LOG_UNHANDLED("libdwarf: Const Type\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            // NOTE(mateusz): Some DW_TAG_const_type are empty
            if(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error) == DW_DLV_OK)
            {
                di_const_type *CType = &DI->ConstTypes[DI->ConstTypesCount++];
                Dwarf_Off DIEOffset = 0;
                DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
                CType->DIEOffset = DIEOffset;
                
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
                            assert(!"Not expected TAG!");
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_restrict_type:
        {
            //LOG_UNHANDLED("libdwarf: Restrict Type\n");
            
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_restrict_type *RType = &DI->RestrictTypes[DI->RestrictTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            RType->DIEOffset = DIEOffset;
            
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
            //LOG_UNHANDLED("libdwarf: Strcture Type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_struct_type *StructType = &DI->StructTypes[DI->StructTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            StructType->DIEOffset = DIEOffset;
            
            WasUnion = false;
            WasStruct = true;
            
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
                        StructType->Name = ArrayPush(DI->Arena, char, Size);
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
                            LOG_UNHANDLED("Structure type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_union_type:
        {
            //LOG_UNHANDLED("libdwarf: Union Type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_union_type *UnionType = &DI->UnionTypes[DI->UnionTypesCount++];
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            UnionType->DIEOffset = DIEOffset;
            UnionType->Name = "";
            
            WasUnion = true;
            WasStruct = false;
            
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
                        UnionType->Name = ArrayPush(DI->Arena, char, Size);
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
                            LOG_UNHANDLED("Union type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_member:
        {
            //LOG_UNHANDLED("libdwarf: Strcture/Union member\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            if(!WasStruct && !WasUnion)
            {
                LOG_UNHANDLED("Unhandled class type\n");
                return;
            }
            
            if(WasStruct)
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
                            Member->Name = ArrayPush(DI->Arena, char, Size);
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
                                LOG_UNHANDLED("Structure member unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
            else if(WasUnion)
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
                            Member->Name = ArrayPush(DI->Arena, char, Size);
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
                                LOG_UNHANDLED("Unionure member unhandled Attribute: %s\n", AttrName);
                            }
                        }break;
                    }
                }
            }
        }break;
        case DW_TAG_array_type:
        {
            //LOG_UNHANDLED("libdwarf: Array type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
            di_array_type *AType = &DI->ArrayTypes[DI->ArrayTypesCount++];
            
            Dwarf_Off DIEOffset = 0;
            DWARF_CALL(dwarf_die_CU_offset(DIE, &DIEOffset, Error));
            AType->DIEOffset = DIEOffset;
            
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
                            LOG_UNHANDLED("Array type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        case DW_TAG_subrange_type:
        {
            //LOG_UNHANDLED("libdwarf: Subrange type\n");
            Dwarf_Signed AttrCount = 0;
            Dwarf_Attribute *AttrList = {};
            DWARF_CALL(dwarf_attrlist(DIE, &AttrList, &AttrCount, Error));
            
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
                            LOG_UNHANDLED("Array type unhandled Attribute: %s\n", AttrName);
                        }
                    }break;
                }
            }
        }break;
        default:
        {
            const char *TagName = 0x0;
            DWARF_CALL(dwarf_get_TAG_name(Tag, &TagName));
            LOG_UNHANDLED("Unhandled Tag: %s\n", TagName);
        }break;
    }
    
    Dwarf_Die ChildDIE = 0;
    i32 Result = dwarf_child(CurrentDIE, &ChildDIE, Error);
    
    if(Result == DW_DLV_OK)
    { 
        DWARFReadDIEs(Debug, ChildDIE);
        Dwarf_Die SiblingDIE = ChildDIE;
        while(Result == DW_DLV_OK)
        {
            CurrentDIE = SiblingDIE;
            Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, Error);
            if(Result == DW_DLV_OK)
            {
                DWARFReadDIEs(Debug, SiblingDIE);
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
DWARFCountTags(Dwarf_Debug Debug, Dwarf_Die DIE, u32 CountTable[DWARF_TAGS_COUNT])
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
        DWARFCountTags(Debug, ChildDIE, CountTable);
        Dwarf_Die SiblingDIE = ChildDIE;
        while(Result == DW_DLV_OK)
        {
            CurrentDIE = SiblingDIE;
            Result = dwarf_siblingof(Debug, CurrentDIE, &SiblingDIE, Error);
            if(Result == DW_DLV_OK)
            {
                DWARFCountTags(Debug, SiblingDIE, CountTable);
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
    Dwarf_Unsigned CUHeaderLength = 0;
    Dwarf_Half Version = 0;
    Dwarf_Unsigned AbbrevOffset = 0;
    Dwarf_Half AddressSize = 0;
    Dwarf_Unsigned NextCUHeader = 0;
    Dwarf_Error *Error = 0x0;
    
    OpenDwarfSymbolsHandle();
    
    u32 *CountTable = (u32 *)calloc(DWARF_TAGS_COUNT, sizeof(u32));
    DI->Arena = ArenaCreateZeros(Kilobytes(4096));
    
    for(i32 CUCount = 0;;++CUCount) {
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
        
        DWARFCountTags(DI->Debug, CurrentDIE, CountTable);
    }
    
    //TIMER_START(0);
    
    DI->CompileUnits = ArrayPush(DI->Arena, di_compile_unit, CountTable[DW_TAG_compile_unit]);
    DI->Functions = ArrayPush(DI->Arena, di_function, CountTable[DW_TAG_subprogram]);
    DI->BaseTypes = ArrayPush(DI->Arena, di_base_type, CountTable[DW_TAG_base_type]);
    DI->Typedefs = ArrayPush(DI->Arena, di_typedef, CountTable[DW_TAG_typedef]);
    DI->PointerTypes = ArrayPush(DI->Arena, di_pointer_type, CountTable[DW_TAG_pointer_type]);
    DI->ConstTypes = ArrayPush(DI->Arena, di_const_type, CountTable[DW_TAG_const_type]);
    DI->RestrictTypes = ArrayPush(DI->Arena, di_restrict_type, CountTable[DW_TAG_restrict_type]);
    DI->Variables = ArrayPush(DI->Arena, di_variable, CountTable[DW_TAG_variable]);
    DI->Params = ArrayPush(DI->Arena, di_variable, CountTable[DW_TAG_formal_parameter]);
    DI->LexScopes = ArrayPush(DI->Arena, di_lexical_scope, CountTable[DW_TAG_lexical_block]);
    DI->StructMembers = ArrayPush(DI->Arena, di_struct_member, CountTable[DW_TAG_member]);
    DI->StructTypes = ArrayPush(DI->Arena, di_struct_type, CountTable[DW_TAG_structure_type]);
    DI->UnionMembers = ArrayPush(DI->Arena, di_union_member, CountTable[DW_TAG_member]);
    DI->UnionTypes = ArrayPush(DI->Arena, di_union_type, CountTable[DW_TAG_union_type]);
    DI->ArrayTypes = ArrayPush(DI->Arena, di_array_type, CountTable[DW_TAG_array_type]);
    DI->SourceFiles = ArrayPush(DI->Arena, di_src_file, MAX_DI_SOURCE_FILES);

#if 0
    for(u32 I = 0; I < DWARF_TAGS_COUNT; I++)
    {
        if(CountTable[I])
        {
            const char *A = 0x0;
            dwarf_get_TAG_name(I, &A);
            printf("[%s]: %d\n", A, CountTable[I]);
        }
    }
#endif
    
    //TIMER_END(0);
    
    for(i32 CUCount = 0;;++CUCount) {
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
        
        DWARFReadDIEs(DI->Debug, CurrentDIE);
    }
    
    CloseDwarfSymbolsHandle();
    
    // NOTE(mateusz): This time without finish to preserve it
    OpenDwarfSymbolsHandle();
    Dwarf_Cie *CIEs;
    Dwarf_Signed CIECount;
    Dwarf_Fde *FDEs;
    Dwarf_Signed FDECount;
    DWARF_CALL(dwarf_get_fde_list_eh(DI->Debug, &CIEs, &CIECount, &FDEs, &FDECount, Error));
    
    di_frame_info *Frame = &DI->FrameInfo;
    Frame->CIECount = CIECount;
    Frame->FDECount = FDECount;
    Frame->CIEs = CIEs;
    Frame->FDEs = FDEs;
    
    free(CountTable);
}

static size_t
DWARFGetCFA(size_t PC)
{
    di_frame_info *Frame = &DI->FrameInfo;
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
            size_t RegVal = GetRegisterByABINumber(Regs, RegnumOut);
            
            //printf("RegVal = %lX, OffsetOut = %llX, RegVal + OffsetOut = %lX\n", RegVal, OffsetOut, (size_t)((ssize_t)RegVal + (ssize_t)OffsetOut));
            return RegVal + OffsetOut;
        }
    }
    
    assert(false);
    return PC;
}

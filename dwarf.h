/* date = November 28th 2020 3:15 pm */

#ifndef DWARF_H
#define DWARF_H

// NOTE(mateusz): With DWARF5 and non-platform specifc it's DW_TAG_immutable_type
// TODO(mateusz): Yea but GCC and Clang are going to stick their shitty ideas about things
// to this and we really need a hashmap
#define DWARF_TAGS_COUNT 0xffff

enum
{
    DI_COMP_UNIT_NULL = 0x0,
    DI_COMP_UNIT_HAS_RANGES = 0x1,
};

typedef i32 di_compile_unit_flags;

struct di_compile_unit
{
    char *Name;
    size_t Offset;
    
    size_t *RangesLowPCs;
    size_t *RangesHighPCs;
    u32 RangesCount = 0;
    
    di_compile_unit_flags Flags;
};

struct di_src_line_loc
{
    size_t Address;
    i32 FileNumber;
    u32 NOInFile;
};

struct di_src_line
{
    size_t Address;
    u32 LineNum;
    u32 SrcFileIndex;
};

struct di_src_file
{
    char *Path;
    char **Content;
    u32 ContentLineCount;
    di_src_line *Lines;
    u32 SrcLineCount;
};

struct di_variable
{
    char *Name;
    
    size_t TypeOffset;
    u8 LocationAtom;
    ssize_t Offset;
};

struct di_frame_info
{
    Dwarf_Cie *CIEs;
    Dwarf_Signed CIECount;
    Dwarf_Fde *FDEs;
    Dwarf_Signed FDECount;
};

struct di_lexical_scope
{
    // NOTE(mateusz): If RangesCount == 0, then address information is stored
    // in LowPC and HighPC, otherwise, LowPC and HighPC are zeroed and addresses
    // are stores in RangesLowPCs and RangesHighPCs and there are RangesCount of them
    size_t LowPC;
    size_t HighPC;
    size_t *RangesLowPCs;
    size_t *RangesHighPCs;
    u32 RangesCount = 0;
    
    di_variable *Variables;
    u32 VariablesCount;
};

struct di_function
{
    char *Name;
    
    size_t TypeOffset;
    bool FrameBaseIsCFA;
    di_variable *Params;
    u32 ParamCount;
    di_lexical_scope FuncLexScope;
    di_lexical_scope *LexScopes;
    u32 LexScopesCount;
};

enum
{
    TYPE_NONE = 0,
    TYPE_IS_BASE = (1 << 0),
    TYPE_IS_TYPEDEF = (1 << 1),
    TYPE_IS_POINTER = (1 << 2),
    TYPE_IS_CONST = (1 << 3),
    TYPE_IS_RESTRICT = (1 << 4),
    TYPE_IS_STRUCT = (1 << 5),
    TYPE_IS_UNION = (1 << 6),
    TYPE_IS_ARRAY = (1 << 7),
};

typedef i32 type_flags;

struct di_base_type
{
    char *Name;
    size_t DIEOffset;
    u32 ByteSize;
    u32 Encoding;
};

struct di_typedef
{
    char *Name;
    size_t DIEOffset;
    size_t ActualTypeOffset;
};

struct di_pointer_type
{
    size_t DIEOffset;
    size_t ActualTypeOffset;
};

struct di_const_type
{
    size_t DIEOffset;
    size_t ActualTypeOffset;
};

struct di_restrict_type
{
    size_t DIEOffset;
    size_t ActualTypeOffset;
};

struct di_struct_member
{
    char *Name;
    
    size_t ActualTypeOffset;
    u32 ByteLocation;
};

struct di_struct_type
{
    char *Name;
    
    size_t DIEOffset;
    size_t ByteSize;
    di_struct_member *Members;
    u32 MembersCount;
};

struct di_union_member
{
    char *Name;
    
    size_t ActualTypeOffset;
    u32 ByteLocation;
};

struct di_union_type
{
    char *Name;
    
    size_t DIEOffset;
    size_t ByteSize;
    di_union_member *Members;
    u32 MembersCount;
};

struct di_array_type
{
    size_t DIEOffset;
    size_t ActualTypeOffset;
    size_t RangesTypeOffset;
    size_t UpperBound;
};

struct di_underlaying_type
{
    char *Name;
    
    union
    {
        void *Ptr;
        di_struct_type *Struct;
        di_union_type *Union;
        di_base_type *Type;
    };
    
    size_t ArrayUpperBound;
    u32 PointerCount;
    type_flags Flags;
};

#define MAX_DI_SOURCE_FILES 8
#define MAX_DI_SOURCE_LINES (1 << 15)

struct debug_info
{
    arena *Arena;
    
    di_src_file *SourceFiles;
    u32 SourceFilesCount;
    u32 SourceFilesInExec;
    
    di_variable *Variables;
    u32 VariablesCount;
    
    di_variable *Params;
    u32 ParamsCount;
    
    di_lexical_scope *LexScopes;
    u32 LexScopesCount;
    
    di_function *Functions;
    u32 FuctionsCount;
    
    di_compile_unit *CompileUnits;
    u32 CompileUnitsCount;
    
    di_base_type *BaseTypes;
    u32 BaseTypesCount;
    
    di_typedef *Typedefs;
    u32 TypedefsCount;
    
    di_pointer_type *PointerTypes;
    u32 PointerTypesCount;
    
    di_const_type *ConstTypes;
    u32 ConstTypesCount;
    
    di_restrict_type *RestrictTypes;
    u32 RestrictTypesCount;
    
    di_struct_member *StructMembers;
    u32 StructMembersCount;
    
    di_struct_type *StructTypes;
    u32 StructTypesCount;
    
    di_union_member *UnionMembers;
    u32 UnionMembersCount;
    
    di_union_type *UnionTypes;
    u32 UnionTypesCount;
    
    di_array_type *ArrayTypes;
    u32 ArrayTypesCount;
    
    di_frame_info FrameInfo;
    Dwarf_Debug Debug;
    int DwarfFd;

    i32 DIEIndentLevel;
    i32 LastUnionIndent;
};

static bool AddressInAnyCompileUnit(size_t Address);
static bool AddressInCompileUnit(di_compile_unit *CU, size_t Address);
static address_range AddressRangeCurrentAndNextLine(size_t StartAddress);
static bool BaseTypeIsDoubleFloat(di_base_type *Type);
static bool BaseTypeIsFloat(di_base_type *Type);
static char *BaseTypeToFormatStr(di_base_type *Type, type_flags TFlag);
static void CloseDwarfSymbolsHandle();
static u32 CountLinesInFileIndex(Dwarf_Line *Lines, u32 LineCount, u32 FileIdx);
static void DWARFCountTags(Dwarf_Debug Debug, Dwarf_Die DIE, u32 CountTable[DWARF_TAGS_COUNT]);
static size_t DWARFGetCFA(size_t PC);
static void DWARFRead();
static void DWARFReadDIEs(Dwarf_Debug Debug, Dwarf_Die DIE);
static void DumpLinesMatchingIndex(Dwarf_Line *Lines, u32 LineCount, di_src_file *File, u32 FileIdx, u32 LineNum, u32 *LineIdxOut);
static Dwarf_Die FindDIEWithOffset(Dwarf_Debug Debug, Dwarf_Die DIE, size_t Offset);
static size_t FindEntryPointAddress();
static di_function *FindFunctionConfiningAddress(size_t Address);
static di_src_file *FindSourceFile(char *Path);
static di_underlaying_type FindUnderlayingType(size_t BTDIEOffset);
static size_t GetDebugeeLoadAddress(i32 DebugeePID);
static di_src_line *LineFindByNumber(u32 LineNum, u32 SrcFileIndex);
static di_src_line *LineTableFindByAddress(size_t Address);
static bool LoadSourceContaingAddress(size_t Address, u32 *FileIdxOut, u32 *LineIdxOut);
static bool OpenDwarfSymbolsHandle();
static di_src_file *PushSourceFile(char *Path, u32 SrcLineCount);
static di_src_file *PushSourceFile(char *Path);
static u32 SrcFileAssociatePath(char *Path);
static bool FunctionHasAnyVariables(di_function *Func);

#endif //DWARF_H

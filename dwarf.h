/* date = November 28th 2020 3:15 pm */

#ifndef DWARF_H
#define DWARF_H

// NOTE(mateusz): With DWARF5 and non-platform specifc it's DW_TAG_immutable_type
#define DWARF_TAGS_COUNT 0x4b

enum
{
    DI_COMP_UNIT_NULL = 0x0,
    DI_COMP_UNIT_HAS_RANGES = 0x1,
};

typedef i32 di_compile_unit_flags;

struct di_compile_unit
{
    char *Name;
    
    size_t LowPC;
    size_t HighPC;
    //address_range *AddressRanges;
    
    di_compile_unit_flags Flags;
};

struct di_src_file
{
    char *Path;
    char *Content;
    u32 LineCount;
};

struct di_src_line
{
    size_t Address;
    u32 LineNum;
    i32 SrcFileIndex;
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

#define MAX_DI_VARIABLES 16

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

#define MAX_DI_LEX_SCOPES 16

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
    TYPE_IS_STRUCT = (1 << 4),
    TYPE_IS_ARRAY = (1 << 5),
};

typedef i32 type_flags;

struct di_base_type
{
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
    di_struct_member *Members;
    u32 MembersCount;
};

#define MAX_DI_SOURCE_FILES 8
di_src_file *DISourceFiles = 0x0;
u32 DISourceFilesCount = 0;

#define MAX_DI_SOURCE_LINES (1 << 15)
di_src_line *DISourceLines = 0x0;
u32 DISourceLinesCount = 0;

di_variable *DIVariables = 0x0;
u32 DIVariablesCount = 0;

di_variable *DIParams = 0x0;
u32 DIParamsCount = 0;

di_lexical_scope *DILexScopes = 0x0;
u32 DILexScopesCount;

di_function *DIFunctions = 0x0;
u32 DIFuctionsCount = 0;

di_compile_unit *DICompileUnits = 0x0;
u32 DICompileUnitsCount = 0;

di_base_type *DIBaseTypes = 0x0;
u32 DIBaseTypesCount = 0;

di_typedef *DITypedefs = 0x0;
u32 DITypedefsCount = 0;

di_pointer_type *DIPointerTypes;
u32 DIPointerTypesCount = 0;

di_struct_member *DIStructMembers = 0x0;
u32 DIStructMembersCount = 0;

di_struct_type *DIStructTypes = 0x0;
u32 DIStructTypesCount = 0;

di_frame_info DIFrameInfo = {};
Dwarf_Debug Debug = 0;

arena *DIArena = 0x0;

#endif //DWARF_H

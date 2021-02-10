/* date = November 28th 2020 3:15 pm */

#ifndef DWARF_H
#define DWARF_H

// NOTE(mateusz): With DWARF5 and non-platform specifc it's DW_TAG_immutable_type
// TODO(mateusz): Yea but GCC and Clang are going to stick their shitty ideas about things
// to this and we really need a hashmap
#define DWARF_TAGS_COUNT 0xffff

#ifdef DEBUG
#define LOG_DWARF(fmt, ...) if(Debuger.Log.DwarfLogs) { printf(fmt, ##__VA_ARGS__); }
#else
#define LOG_DWARF(...) do { } while (0)
#endif

enum
{
    DI_COMP_UNIT_NULL = 0x0,
    DI_COMP_UNIT_HAS_RANGES = 0x1,
};

typedef i32 di_compile_unit_flags;

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

struct di_exec_src_file_flags
{
    u8 ShowToUser: 1;
};

struct di_exec_src_file
{
    char *Name;
    char *Dir;
    i32 DwarfIndex;
    di_exec_src_file_flags Flags;
};

struct di_compile_unit;
struct di_exec_src_file_bucket
{
    di_exec_src_file_bucket *Next;
    di_exec_src_file *Files;
    di_compile_unit *CU;
    u32 Count;
};

struct di_exec_src_file_list
{
    di_exec_src_file_bucket *Head;
    di_exec_src_file_bucket *Tail;
    u32 Count;
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

struct di_compile_unit
{
    char *Name;
    size_t Offset;
    
    size_t *RangesLowPCs;
    size_t *RangesHighPCs;
    u32 RangesCount = 0;
    
    di_compile_unit_flags Flags;

    di_variable *GlobalVariables;
    u32 GlobalVariablesCount;
    di_variable *Variables;
    di_function *Functions;
};

#define MAX_DI_SOURCE_FILES 8

struct debug_info
{
    arena Arena;
    
    di_src_file *SourceFiles;
    u32 SourceFilesCount;

    di_exec_src_file_list ExecSrcFileList;

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

    i32 CFAFd = 0;
    Dwarf_Debug CFADebug = 0;

    i32 DIEIndentLevel;
    i32 LastUnionIndent;
    
    bool WasStruct = false;
    bool WasUnion = false;
};

/*
 * Dwarf functions prototypes
 */
static bool     DwarfOpenSymbolsHandle(i32 *Fd, Dwarf_Debug *Debug);
static void     DwarfCloseSymbolsHandle(i32 *Fd, Dwarf_Debug *Debug);
static void     DwarfReadDIE(Dwarf_Debug Debug, Dwarf_Die DIE);
static void     DwarfReadDIEMany(Dwarf_Debug Debug, Dwarf_Die DIE);
static void     DwarfCountTags(Dwarf_Debug Debug, Dwarf_Die DIE, u32 CountTable[DWARF_TAGS_COUNT]);
static void     DwarfRead();

/*
 * Dwarf internal representation functions
 */
static Dwarf_Die DwarfFindDIEByOffset(Dwarf_Debug Debug, Dwarf_Die DIE, size_t Offset);

/*
 * Source files functions
 */
static di_src_file *    DwarfFindSourceFileByPath(char *Path);
static di_src_file *    DwarfPushSourceFile(char *Path, u32 SrcLineCount);
static u32              DwarfCountSourceFileLines(Dwarf_Line *Lines, u32 LineCount, u32 FileIdx);
static void             DwarfLoadSourceFileByIndex(Dwarf_Line *Lines, u32 LineCount, di_src_file *File, u32 FileIdx, u32 LineNum, u32 *LineIdxOut);
static void             DwarfLoadSourceFileFromCU(di_compile_unit *CU, di_exec_src_file *File);
static bool             DwarfLoadSourceFileByAddress(size_t Address, u32 *FileIdxOut, u32 *LineIdxOut);

/*
 * Source lines functions
 */
static di_src_line *    DwarfFindLineByAddress(size_t Address);
static di_src_line *    DwarfFindLineByNumber(u32 LineNum, u32 SrcFileIndex);
static address_range    DwarfGetAddressRangeUntilNextLine(size_t StartAddress);
static bool             DwarfIsAddressInDifferentSourceLine(size_t Address);

/*
 * Functions functions
 */
static bool             DwarfAddressConfinedByFunction(di_function *Func, size_t Address);
static di_function *    DwarfFindFunctionByAddress(size_t Address);
static di_variable *    DwarfGetFunctionsFirstVariable(di_function *Func);
static size_t           DwarfFindEntryPointAddress();

/*
 * Variables types functions
 */
static di_underlaying_type  DwarFindUnderlayingType(size_t BTDIEOffset);
static char *               DwarfBaseTypeToFormatStr(di_base_type *Type, type_flags TFlag);
static bool                 DwarfBaseTypeIsFloat(di_base_type *Type);
static bool                 DwarfBaseTypeIsDoubleFloat(di_base_type *Type);

/*
 * Lexical scopes functions
 */
static bool DwarfAddressConfinedByLexicalScope(di_lexical_scope *LexScope, size_t Address);

/*
 * Compile units functions
 */
static di_compile_unit *    DwarfFindCompileUnitByAddress(size_t Address);
static bool                 DwarfAddressConfinedByCompileUnit(di_compile_unit *CU, size_t Address);

/*
 * .debug_frame and .eh_frame functions
 */
static bool     DwarfAddressInFrame(size_t Address);
static bool     DwarfEvalFDE(size_t Address, u32 RegsTableSize, Dwarf_Regtable3 *Result);
static size_t   DwarfCalculateCFA(Dwarf_Regtable3 *Table, x64_registers Registers);
static size_t   DwarfGetCFA(size_t Address);

/*
 * Elf related functions
 */
static bool DwarfIsExectuablePIE();

#endif //DWARF_H

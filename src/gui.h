/* date = January 1st 2021 0:47 pm */

#ifndef GUI_H
#define GUI_H

struct function_representation
{
    char *Label;
    di_function *ActualFunction;
};

struct variable_representation
{
    char *Name;
    char *ValueString;
    char *TypeString;
    size_t Address;
    di_underlaying_type Underlaying;
    di_variable *ActualVariable;
    u32 DerefCount;
    
    variable_representation *Children;
    u32 ChildrenCount;
};

struct variable_representation_node
{
    variable_representation Var;
    variable_representation_node *Next;
};

struct variable_representation_list
{
    variable_representation_node *Head;
    variable_representation_node *Tail;
    u32 Count;
};

enum
{
    COMBO_REG_SHOW_AS_DEFAULT = 0,
    COMBO_REG_SHOW_AS_FLOAT = 1,
    COMBO_REG_SHOW_AS_DOUBLE = 2,
    COMBO_REG_SHOW_AS_INT8 = 3,
    COMBO_REG_SHOW_AS_INT16 = 4,
    COMBO_REG_SHOW_AS_INT32 = 5,
    COMBO_REG_SHOW_AS_INT64 = 6,
};

typedef u8 ShowRegisterAsState;

struct gui_flags
{
    u8 RegsShowMMX : 1;
    u8 RegsShowSSE : 1;
    u8 RegsShowAVX : 1;
    u8 RegsShowAs : 4;
    u8 VarShowGlobals : 1;
    u8 VarShowParams : 1;
    u8 VarShowLocals : 1;
};

enum
{
    VarEditKind_Name,
    VarEditKind_Value,
};

typedef u8 var_edit_kind;

struct gui_transient
{
    arena RepresentationArena;
	
    function_representation *FuncRepresentation;
    u32 FuncRepresentationCount;

    bool EnterCaptured;
    variable_representation *Variables;
    u32 VariableCnt;
    size_t LocalsBuildAddress;
    variable_representation *VarInEdit;
    var_edit_kind VarEditKind;
    char VarValueEditBuffer[128];
    char VarNameEditBuffer[128];

    arena WatchArena;
    char WatchBuffer[128];
    variable_representation_list WatchVars;
    size_t WatchBuildAddress;
    char *WatchInputError;

    bool CloseNextTree;
};

struct gui_data
{
    arena Arena;
    char *StatusText;
    char BreakFuncName[128];
    char BreakAddress[32];
    void (* ModalFuncShow)();
    ImTextureID BreakpointTextureActive;
    ImTextureID BreakpointTextureBlank;
    ImFont *BiggerFont;

    gui_transient Transient;

    char *SpacesArray[10];
    u32 WindowWidth = 1024;
    u32 WindowHeight = 768;
    gui_flags Flags;

    gui_data()
    {
        this->Arena = ArenaCreate(Kilobytes(4));
        this->Transient.RepresentationArena = ArenaCreate(Kilobytes(32));
        this->Transient.WatchArena = ArenaCreate(Kilobytes(16));
    }

#ifdef DEBAG
    ~gui_data()
    {
        ArenaDestroy(this->Arena);
        ArenaDestroy(this->RepresentationArena);
    }
#endif
};


ImVec4 CurrentLineColor = ImVec4(1.0f, 1.0f, 0.0f, 1.0f);
ImVec4 BreakpointLineColor = ImVec4(1.0f, 0.0f, 0.0f, 1.0f);

gui_data _Gui = {};
gui_data *Gui = &_Gui;

const u32 TEX_WIDTH =   16;
const u32 TEX_HEIGHT =  16;
const u32 PNG_CHANNEL = 4;

#ifdef DEBUG
#define LOG_GUI(fmt, ...) if(Debuger.Log.FlowLogs) { printf(fmt, ##__VA_ARGS__); }
#else
#define LOG_GUI(...) do { } while (0)
#endif

static void GuiInit();
static void GuiEndFrame();
static void GuiShowArrayType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName);
static void GuiShowBreakAtAddress();
static void GuiShowBreakAtFunction();
static void GuiShowVarInputText(char *Label, char *Buffer, u32 BufferSize);
static void GuiShowRegisters(x64_registers Regs);
static void GuiStartFrame();
static void _GuiShowBreakAtAddressModalWindow();
static void _GuiShowBreakAtFunctionWindow();
static void GuiSetStatusText(char *Str);
static void GuiClearStatusText();
static void GuiCreateBreakpointTexture();
static variable_representation GuiCopyVariableRepresentation(variable_representation *Var, arena *Arena);
static variable_representation GuiRebuildVariableRepresentation(variable_representation *Var, arena *Arena);
static variable_representation GuiBuildVariableRepresentation(di_variable *Var, u32 DerefCount, arena *Arena);
static variable_representation GuiBuildVariableRepresentation(size_t TypeOffset, size_t Address, char *Name, u32 DerefCount, arena *Arena);
static void GuiBuildFunctionRepresentation();
static void GuiShowBacktrace();
static void GuiShowWatch();

/*
 * Gui all the variable related functions
 */
static void GuiBeginVariableTable();
static void GuiEndVariableTable();

#endif //GUI_H

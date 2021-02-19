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

struct gui_flags
{
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

struct gui_data
{
    arena Arena;
    arena RepresentationArena;
    char *StatusText;
    char BreakFuncName[128];
    char BreakAddress[32];
    void (* ModalFuncShow)();
    ImTextureID BreakpointTextureActive;
    ImTextureID BreakpointTextureBlank;

    char *SpacesArray[10];
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

    char WatchBuffer[128];
    variable_representation_list WatchVars;
    size_t WatchBuildAddress;

    bool CloseNextTree;

    u32 WindowWidth = 1024;
    u32 WindowHeight = 768;
    gui_flags Flags;

    gui_data()
    {
        this->Arena = ArenaCreate(Kilobytes(4));
        this->RepresentationArena = ArenaCreate(Kilobytes(32));
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
static variable_representation GuiRebuildVariableRepresentation(variable_representation *Var, arena *Arena);
static variable_representation GuiBuildVariableRepresentation(di_variable *Var, u32 DerefCount, arena *Arena);
static variable_representation GuiBuildMemberRepresentation(size_t TypeOffset, size_t Address, char *Name, u32 DerefCount, arena *Arena);
static void GuiBuildFunctionRepresentation();
static void GuiShowBacktrace();
static void GuiShowWatch();

#endif //GUI_H

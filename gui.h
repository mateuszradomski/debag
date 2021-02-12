/* date = January 1st 2021 0:47 pm */

#ifndef GUI_H
#define GUI_H

struct function_representation
{
    char *Label;
    di_function *ActualFunction;
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

    char *SpacesArray[10];
    function_representation *FuncRepresentation;
    u32 FuncRepresentationCount;
    
    u32 WindowWidth = 1024;
    u32 WindowHeight = 768;

    gui_data()
        {
            this->Arena = ArenaCreate(Kilobytes(4));
        }
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

static void GuiEndFrame();
static void GuiShowArrayType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName);
static void GuiShowBaseType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName);
static void GuiShowBreakAtAddress();
static void GuiShowBreakAtFunction();
static void GuiShowRegisters(x64_registers Regs);
static void GuiShowStructType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName);
static void GuiShowValueAsString(size_t DereferencedAddress);
static void GuiShowVariable(size_t TypeOffset, size_t VarAddress, char *VarName);
static void GuiShowVariable(di_variable *Var, size_t FBReg);
static void GuiStartFrame();
static void _GuiShowBreakAtAddressModalWindow();
static void _GuiShowBreakAtFunctionWindow();
static void GuiSetStatusText(char *Str);
static void GuiClearStatusText();
static void GuiCreateBreakpointTexture();
static void GuiBuildFunctionRepresentation();
static void GuiShowBacktrace();

#endif //GUI_H

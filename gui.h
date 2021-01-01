/* date = January 1st 2021 0:47 pm */

#ifndef GUI_H
#define GUI_H

struct gui_data
{
    arena *Arena;
    char *StatusText;
    char BreakFuncName[128];
    char BreakAddress[32];
    void (* ModalFuncShow)();
    
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

static void ImGuiEndFrame();
static void ImGuiShowArrayType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName);
static void ImGuiShowBaseType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName);
static void ImGuiShowBreakAtAddress();
static void ImGuiShowBreakAtFunction();
static void ImGuiShowRegisters(x64_registers Regs);
static void ImGuiShowStructType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName);
static void ImGuiShowValueAsString(size_t DereferencedAddress);
static void ImGuiShowVariable(size_t TypeOffset, size_t VarAddress, char *VarName);
static void ImGuiShowVariable(di_variable *Var, size_t FBReg);
static void ImGuiStartFrame();
static void _ImGuiShowBreakAtAddressModalWindow();
static void _ImGuiShowBreakAtFunctionModalWindow();
static void GuiSetStatusText(char *Str);

#endif //GUI_H
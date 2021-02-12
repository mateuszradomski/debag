static void
GuiStartFrame()
{
    ImGui_ImplOpenGL2_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
}

static void
GuiEndFrame()
{
    ImGui::Render();
    ImGui_ImplOpenGL2_RenderDrawData(ImGui::GetDrawData());
}

static void
GuiShowRegisters(x64_registers Regs)
{
    ImGui::PushStyleVar(ImGuiStyleVar_ItemInnerSpacing, ImVec2(2, 0));
    ImGui::Text("RIP: %lX", Regs.RIP);
    ImGui::PopStyleVar();

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(1, 0));
    ImGui::Separator();
    
    ImGui::Columns(4, 0x0, true);

    // NOTE(mateusz): We ignore we registers that are the last 11 in the 'x64_registers' struct
    u32 IgnoreCount = 11;
    
    for(u32 I = 0; I < (sizeof(Regs) / sizeof(size_t)) - IgnoreCount; I++)
    {
        ImGui::Text("%s: %lX", RegisterGetNameByUnionIndex(I), Regs.Array[I]);
        ImGui::NextColumn();
    }

    ImGui::Columns(1);
    ImGui::PopStyleVar();
    
    ImGui::Separator();
}

static void
GuiShowBreakpoints()
{
    for(u32 I = 0; I < BreakpointCount; I++)
    {
        breakpoint *BP = &Breakpoints[I];

        ImVec4 Color = {};
        char *StateString = 0x0;
        if(BP->State.Enabled)
        {
            Color = ImVec4(0.0f, 0.8f, 0.2f, 1.0f);
            StateString = "Enabled";
        }
        else
        {
            Color = ImVec4(0.8f, 0.2f, 0.0f, 1.0f);
            StateString = "Disabled";
        }

        if(BP->SourceLine == 0)
        {
            ImGui::TextColored(Color, "Breakpoint at %lX [%s]\n", BP->Address, StateString);
        }
        else
        {
            char *FileName = StringFindLastChar(DI->SourceFiles[BP->FileIndex].Path, '/') + 1;
            ImGui::TextColored(Color, "Breakpoint at %s:%u (%lX) [%s]\n",
                               FileName, BP->SourceLine, BP->Address, StateString);
        }
    }
}

static void
GuiShowValueAsString(size_t DereferencedAddress)
{
    char Temp[256] = {};
    u32 TIndex = 0;
    
    Temp[TIndex++] = '\"';
    if(DereferencedAddress)
    {
        size_t MachineWord = DebugeePeekMemory(DereferencedAddress);
        char *PChar = (char *)&MachineWord;
        
        int RemainingBytes = sizeof(MachineWord);
        while(PChar[0] && IS_PRINTABLE(PChar[0]))
        {
            if(TIndex == sizeof(Temp) - 8)
            {
                assert(RemainingBytes);

                if(PChar[0])
                {
                    for(u32 i = 0; i < 5; i++) { Temp[TIndex++] = '.'; }
                }
                
                break;
            }

            Temp[TIndex++] = PChar[0];
            PChar += 1;
            
            RemainingBytes -= 1;
            if(RemainingBytes == 0)
            {
                RemainingBytes = sizeof(MachineWord);
                DereferencedAddress += sizeof(MachineWord);
                
                MachineWord = DebugeePeekMemory(DereferencedAddress);
                PChar = (char *)&MachineWord;
            }
        }
    }
    
    Temp[TIndex++] = '\"';
    assert(TIndex < sizeof(Temp));

    char AddrTemp[24] = {};
    if(sizeof(AddrTemp) < sizeof(Temp) - TIndex)
    {
        sprintf(AddrTemp, " (%p)", (void *)DereferencedAddress);
    
        for(u32 I = 0; I < sizeof(AddrTemp); I++)
        {
            Temp[TIndex++] = AddrTemp[I];
        }
        assert(TIndex < sizeof(Temp));
    }
    
    ImGui::Text("%s", Temp);
}

static void
GuiShowStructType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    di_struct_type *Struct = Underlaying.Struct;
    size_t MachineWord = DebugeePeekMemory(VarAddress);
    
    char TypeName[128] = {};
    StringConcat(TypeName, Underlaying.Name);

    // TODO(mateusz): Stacked pointers dereference, like (void **)
    if(Underlaying.Flags.IsPointer)
    {
        if(Underlaying.PointerCount == 1)
        {
            VarAddress = MachineWord;
        }
        
        StringConcat(TypeName, " ");
        for(u32 I = 0; I < Underlaying.PointerCount; I++)
        {
            StringConcat(TypeName, "*");
        }
    }
    
    // Anonymous union
    if(StringEmpty(VarName))
    {
        for(u32 MemberIndex = 0; MemberIndex < Struct->MembersCount; MemberIndex++)
        {
            di_struct_member *Member = &Struct->Members[MemberIndex];
            size_t MemberAddress = VarAddress + Member->ByteLocation;
            assert(Member->Name);
            
            GuiShowVariable(Member->ActualTypeOffset, MemberAddress, Member->Name);
        }
    }
    else
    {
        bool AddressNonNull = VarAddress != 0x0;
        bool NonStackedPointer = Underlaying.PointerCount < 2;
        bool Open = false;
        
        if(AddressNonNull && NonStackedPointer) {
            Open = ImGui::TreeNode(VarName, "%s", VarName);
        } else {
            ImGui::Text("%s", VarName);
        } ImGui::NextColumn();
        
        ImGui::Text("0x%lx", VarAddress); ImGui::NextColumn();
        ImGui::Text("%s", TypeName); ImGui::NextColumn();
        
        if(Open)
        {
            for(u32 MemberIndex = 0; MemberIndex < Struct->MembersCount; MemberIndex++)
            {
                di_struct_member *Member = &Struct->Members[MemberIndex];
                size_t MemberAddress = VarAddress + Member->ByteLocation;
                assert(Member->Name);
                
                GuiShowVariable(Member->ActualTypeOffset, MemberAddress, Member->Name);
            }
            
            ImGui::TreePop();
        }
    }
}

static void
GuiShowArrayType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    char TypeName[128] = {};
    strcat(TypeName, Underlaying.Name);
    size_t MachineWord = DebugeePeekMemory(VarAddress);
    
    // TODO(mateusz): Stacked pointers dereference, like (void **)
    if(Underlaying.Flags.IsPointer)
    {
        VarAddress = MachineWord;
        
        StringConcat(TypeName, " ");
        for(u32 I = 0; I < Underlaying.PointerCount; I++)
        {
            StringConcat(TypeName, "*");
        }
    }
    
    bool Open = ImGui::TreeNode(VarName, "%s", VarName);
    ImGui::NextColumn();
    if(Underlaying.Type->Encoding == DW_ATE_signed_char)
    {
        GuiShowValueAsString(VarAddress);
    }
    else
    {
        ImGui::Text("0x%lx", VarAddress);
    }
    
    ImGui::NextColumn();
    ImGui::Text("%s[%ld]", TypeName, Underlaying.ArrayUpperBound + 1);
    ImGui::NextColumn();
    
    if(Open)
    {
        for(u32 I = 0; I <= Underlaying.ArrayUpperBound; I++)
        {
            //size_t MachineWord = DebugeePeekMemory(VarAddress, Debugee.PID);
            
            if(Underlaying.Flags.IsStruct || Underlaying.Flags.IsUnion)
            {
                char VarNameWI[128] = {};
                sprintf(VarNameWI, "%s[%d]", VarName, I);
                
                GuiShowStructType(Underlaying, VarAddress, VarNameWI);
                
                VarAddress += Underlaying.Struct->ByteSize;
            }
            else if(Underlaying.Flags.IsBase)
            {
                char VarNameWI[128] = {};
                sprintf(VarNameWI, "%s[%d]", VarName, I);
                
                //GuiShowBaseType(Underlaying, VarAddress, VarNameWI);
                
                VarAddress += Underlaying.Type->ByteSize;
            }
            else
            {
                LOG_GUI("Var [%s] doesn't have a type\n", VarName);
                //assert(false);
            }
        }
        ImGui::TreePop();
    }
}

static void
GuiShowVariable(size_t TypeOffset, size_t VarAddress, char *VarName = "")
{
    di_underlaying_type Underlaying = DwarfFindUnderlayingType(TypeOffset);
    
    if(Underlaying.Flags.IsArray)
    {
        GuiShowArrayType(Underlaying, VarAddress, VarName);
    }
    else if(Underlaying.Flags.IsStruct || Underlaying.Flags.IsUnion)
    {
        // NOTE(mateusz): We are treating unions and struct as the same thing, but with ByteLocation = 0
        assert(sizeof(di_union_type) == sizeof(di_struct_type));
        assert(sizeof(di_union_member) == sizeof(di_struct_member));
        
        GuiShowStructType(Underlaying, VarAddress, VarName);
    }
    else if(Underlaying.Flags.IsBase)
    {
        //GuiShowBaseType(Underlaying, VarAddress, VarName);
    }
    else
    {
        if(VarName == 0x0)
        {
            LOG_GUI("Var with no name doesn't have a type\n");
        }
        else
        {
            LOG_GUI("Var [%s] doesn't have a type\n", VarName);
        }
        //assert(false);
    }
}

static void
GuiShowVariable(di_variable *Var, size_t FBReg = 0x0)
{
    if(Var->LocationAtom == DW_OP_fbreg)
    {
        size_t VarAddress = FBReg + Var->Offset;
        GuiShowVariable(Var->TypeOffset, VarAddress, Var->Name);
    }
    else if(Var->LocationAtom == DW_OP_addr)
    {
        size_t VarAddress = Debugee.Flags.PIE ? Var->Offset + Debugee.LoadAddress : Var->Offset;
        GuiShowVariable(Var->TypeOffset, VarAddress, Var->Name);
    }
    else if(Var->LocationAtom >= DW_OP_breg0 && Var->LocationAtom <= DW_OP_breg15)
    {
        size_t Register = RegisterGetByABINumber(Debugee.Regs, Var->LocationAtom - DW_OP_breg0);
        size_t VarAddress = Var->Offset + Register;
        
        GuiShowVariable(Var->TypeOffset, VarAddress, Var->Name);
    }
    else
    {
        if(Var && Var->Name)
        {
            const char *OpName = 0x0;
            auto Result = dwarf_get_OP_name(Var->LocationAtom, &OpName);
            if(Result == DW_DLV_OK && OpName)
            {
                LOG_GUI("Cannot show [%s] with %s as OP\n", Var->Name, OpName);
            }
            else
            {
                LOG_GUI("Cannot show Var, Result is nill, LocationAtom = %d\n", Var->LocationAtom);
            }
        }
    }
}

static void
GuiShowVariable(variable_representation *Variable, arena *Arena)
{
    if(Variable->Type.IsBase && !Variable->Type.IsArray)
    {
        ImGui::Text(Variable->Name); ImGui::NextColumn();
        ImGui::Text(Variable->ValueString); ImGui::NextColumn();
        ImGui::Text(Variable->TypeString); ImGui::NextColumn();
    }
    else if((Variable->Type.IsStruct || Variable->Type.IsUnion) && !Variable->Type.IsArray)
    {
        // NOTE(mateusz): We are treating unions and struct as the same thing, but with ByteLocation = 0
        assert(sizeof(di_union_type) == sizeof(di_struct_type));
        assert(sizeof(di_union_member) == sizeof(di_struct_member));

        bool Open = ImGui::TreeNode(Variable->Name); ImGui::NextColumn();
        ImGui::Text(Variable->ValueString); ImGui::NextColumn();
        ImGui::Text(Variable->TypeString); ImGui::NextColumn();

        if(Open)
        {
            if(!Variable->Children)
            {
                // No children, build new
                di_struct_type *Struct = Variable->Underlaying.Struct;
                Variable->Children = (variable_representation *)calloc(1, sizeof(Variable->Children[0]) * Struct->MembersCount);
                Variable->ChildrenCount = Struct->MembersCount;
                
                for(u32 I = 0; I < Struct->MembersCount; I++)
                {
                    di_struct_member *Member = &Struct->Members[I];
                    size_t Address = Variable->Address + Member->ByteLocation;
                    size_t TypeOffset = Member->ActualTypeOffset;
                    char *Name = Member->Name;
                    
                    Variable->Children[I] = GuiBuildMemberRepresentation(TypeOffset, Address, Name, Arena);
                }
            }

            for(u32 I = 0; I < Variable->ChildrenCount; I++)
            {
                GuiShowVariable(&Variable->Children[I], Arena);
            }

            ImGui::TreePop();
        }
    }
    else if(Variable->Type.IsArray)
    {
        bool Open = ImGui::TreeNode(Variable->Name); ImGui::NextColumn();
        ImGui::Text(Variable->ValueString); ImGui::NextColumn();
        ImGui::Text(Variable->TypeString); ImGui::NextColumn();

        if(Open)
        {
            if(!Variable->Children)
            {
                Variable->ChildrenCount = Variable->Underlaying.ArrayUpperBound + 1;
                Variable->Children = (variable_representation *)calloc(1, sizeof(Variable->Children[0]) * Variable->ChildrenCount);

                for(u32 I = 0; I < Variable->ChildrenCount; I++)
                {
                    char *VarNameWI = ArrayPush(Arena, char, StringLength(Variable->Name) + 16);
                    sprintf(VarNameWI, "%s[%d]", Variable->Name, I);

                    size_t TypeOffset = Variable->Underlaying.Type->DIEOffset;
                    size_t Address = Variable->Address + Variable->Underlaying.Type->ByteSize * I;

                    Variable->Children[I] = GuiBuildMemberRepresentation(TypeOffset, Address, VarNameWI, Arena);
                }
            }

            for(u32 I = 0; I < Variable->ChildrenCount; I++)
            {
                GuiShowVariable(&Variable->Children[I], Arena);
            }

            ImGui::TreePop();
        }
    }
    else
    {
    }
}

static void
GuiShowVariables()
{
    size_t PC = DebugeeGetProgramCounter();
    di_compile_unit *CU = DwarfFindCompileUnitByAddress(PC);
    di_function *Func = DwarfFindFunctionByAddress(PC);
    
    size_t ToAllocate = CU ? CU->GlobalVariablesCount : 0;
    if(Func)
    {
        ToAllocate += Func->ParamCount + Func->FuncLexScope.VariablesCount;
        for(u32 I = 0; I < Func->LexScopesCount; I++)
        {
            ToAllocate += Func->LexScopes[I].VariablesCount;
        }
    }

    // TODO: Trasient memory
    scratch_arena Scratch;
    variable_representation *Variables = ArrayPush(Scratch, variable_representation, ToAllocate);
    u32 VariableCnt = 0;

    for(u32 I = 0; CU && I < CU->GlobalVariablesCount; I++)
    {
        di_variable *Var = &CU->GlobalVariables[I];
        if(Var->LocationAtom)
        {
            Variables[VariableCnt++] = GuiBuildVariableRepresentation(Var, Scratch);
        }
    }

    if(Func && Func->FrameBaseIsCFA)
    {
        for(u32 I = 0; I < Func->ParamCount; I++)
        {
            di_variable *Param = &Func->Params[I];
            Variables[VariableCnt++] = GuiBuildVariableRepresentation(Param, Scratch);
        }

        for(u32 I = 0; I < Func->FuncLexScope.VariablesCount; I++)
        {
            di_variable *Var = &Func->FuncLexScope.Variables[I];
            Variables[VariableCnt++] = GuiBuildVariableRepresentation(Var, Scratch);
        }

        for(u32 LexScopeIndex = 0;
            LexScopeIndex < Func->LexScopesCount;
            LexScopeIndex++)
        {
            di_lexical_scope *LexScope = &Func->LexScopes[LexScopeIndex];
            if(DwarfAddressConfinedByLexicalScope(LexScope, DebugeeGetProgramCounter()))
            {
                for(u32 I = 0; I < LexScope->VariablesCount; I++)
                {
                    di_variable *Var = &LexScope->Variables[I];
                    Variables[VariableCnt++] = GuiBuildVariableRepresentation(Var, Scratch);
                }
            }
        }
    }
    else if(Func)
    {
        assert(false);
    }

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(1, 0));
    ImGui::Columns(3, "tree", true);
    ImGui::Text("Name");
    ImGui::NextColumn();
    ImGui::Text("Value");
    ImGui::NextColumn();
    ImGui::Text("Type");
    ImGui::NextColumn();
    ImGui::Separator();

    for(u32 I = 0; I < VariableCnt; I++)
    {
        GuiShowVariable(&Variables[I], Scratch);
    }

    ImGui::Separator();

    ImGui::Columns(1);
    ImGui::PopStyleVar();
}

static void
_GuiShowBreakAtFunctionWindow()
{

    if(KeyboardButtons[GLFW_KEY_ESCAPE].Pressed)
    {
        memset(Gui->BreakFuncName, 0, sizeof(Gui->BreakFuncName));
        Gui->ModalFuncShow = 0x0;
        return;
    }
    if(KeyboardButtons[GLFW_KEY_ENTER].Pressed)
    {
        BreakAtFunctionName(Gui->BreakFuncName);
        memset(Gui->BreakFuncName, 0, sizeof(Gui->BreakFuncName));
        Gui->ModalFuncShow = 0x0;
        return;
    }

    if(!Gui->FuncRepresentation)
    {
        GuiBuildFunctionRepresentation();
    }
    
    ImGuiWindowFlags WinFlags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse;
    ImGui::Begin("Function to set a breakpoint at", 0x0, WinFlags);

    f32 FourFifths = 4.0f / 5.0f;
    ImVec2 WinSize(FourFifths * Gui->WindowWidth, FourFifths * Gui->WindowHeight);
    ImVec2 Center(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
    Center.x -= WinSize.x * 0.5f;
    Center.y -= WinSize.y * 0.5f;

    ImGui::SetWindowSize(WinSize);
    ImGui::SetWindowPos(Center);
    
    ImGui::Text("Enter the function name you wish to set a brekpoint");
    ImGui::Separator();
        
    ImGui::InputText("Name", Gui->BreakFuncName, sizeof(Gui->BreakFuncName));
    
    ImGui::BeginChild("func_list");
    

    for(u32 I = 0; I < Gui->FuncRepresentationCount; I++)
    {
        function_representation *Repr = &Gui->FuncRepresentation[I];
        bool NoInput = StringEmpty(Gui->BreakFuncName);
        if(NoInput || (!NoInput && StringStartsWith(Repr->ActualFunction->Name, Gui->BreakFuncName)))
        {
            if(ImGui::Selectable(Repr->Label))
            {
                Gui->ModalFuncShow = 0x0;
                memset(Gui->BreakFuncName, 0, sizeof(Gui->BreakFuncName));
                BreakAtAddress(Repr->ActualFunction->FuncLexScope.LowPC);
                DebugerUpdateTransient();

                goto END;
                return;
            }
        }
    }

END:;
        
    ImGui::EndChild();

    ImGui::End();
}

static void
GuiShowBreakAtFunction()
{
    char *FuncBreakLabel = "Function to break at"; 
    
    ImGui::OpenPopup(FuncBreakLabel);
    ImVec2 Center(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(Center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    Gui->ModalFuncShow = _GuiShowBreakAtFunctionWindow;
}

static void 
_GuiShowBreakAtAddressModalWindow()
{
    char *AddressBreakLabel = "Address to break at";
    
    if(ImGui::BeginPopupModal(AddressBreakLabel))
    {
        if(KeyboardButtons[GLFW_KEY_ESCAPE].Pressed)
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            memset(Gui->BreakAddress, 0, sizeof(Gui->BreakAddress));
            Gui->ModalFuncShow = 0x0;
            return;
        }

        struct AddressTextFilter
        {
            // Return 0 when we pass and 1 when we don't.
            static int
            LettersWithX(ImGuiInputTextCallbackData* Data)
            {
                if(Data->EventChar < 256 && strchr("0123456789abcdefxABCDEFX", (char)Data->EventChar))
                {
                    return 0; // pass
                }

                return 1; // no pass
            }
        };
        
        ImGui::Text("Enter the address you wish to set a brekpoint, hex or decimal");
        ImGui::Separator();

        ImGui::InputText("Address", Gui->BreakAddress, sizeof(Gui->BreakAddress),
                         ImGuiInputTextFlags_CallbackCharFilter, AddressTextFilter::LettersWithX);
        
        if(ImGui::Button("OK", ImVec2(120, 0)))
        {
            BreakAtAddress(Gui->BreakAddress);
            DebugerUpdateTransient();
            
            ImGui::CloseCurrentPopup(); 
            memset(Gui->BreakAddress, 0, sizeof(Gui->BreakAddress));
            Gui->ModalFuncShow = 0x0;
        }
        
        ImGui::SetItemDefaultFocus();
        ImGui::SameLine();
        if(ImGui::Button("Cancel", ImVec2(120, 0)))
        {
            ImGui::CloseCurrentPopup();
            memset(Gui->BreakAddress, 0, sizeof(Gui->BreakAddress));
            Gui->ModalFuncShow = 0x0;
        }
        ImGui::EndPopup();
    }
}

static void
GuiShowBreakAtAddress()
{
    char *AddressBreakLabel = "Address to break at";
    ImGui::OpenPopup(AddressBreakLabel);
    ImVec2 Center(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(Center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    
    Gui->ModalFuncShow = _GuiShowBreakAtAddressModalWindow;
}

static void
_ImGuiShowOpenFileModalWindow()
{
    if(KeyboardButtons[GLFW_KEY_ESCAPE].Pressed)
    {
        Gui->ModalFuncShow = 0x0;
        return;
    }
    
    ImGuiWindowFlags WinFlags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse;
    ImGui::Begin("File to open", 0x0, WinFlags);

    f32 FourFifths = 4.0f / 5.0f;
    ImVec2 WinSize(FourFifths * Gui->WindowWidth, FourFifths * Gui->WindowHeight);
    ImVec2 Center(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
    Center.x -= WinSize.x * 0.5f;
    Center.y -= WinSize.y * 0.5f;

    ImGui::SetWindowSize(WinSize);
    ImGui::SetWindowPos(Center);
    
    ImGui::Text("Select the file's name you wish to open");
    ImGui::Separator();

    ImGui::BeginChild("options");
    
    for(auto Bucket = DI->ExecSrcFileList.Head; Bucket != 0x0; Bucket = Bucket->Next)
    {
        for(u32 I = 0; I < Bucket->Count; I++)
        {
            di_exec_src_file *File = &Bucket->Files[I];
            
            bool NotInternal = File->Name[0] != '_'; // Generally files with '_' at the start are internal
            bool ShowToUser  = File->Flags.ShowToUser;
            bool CanShow = NotInternal && ShowToUser;
            if(CanShow && ImGui::Selectable(File->Name))
            {
                Gui->ModalFuncShow = 0x0;
                DwarfLoadSourceFileFromCU(Bucket->CU, File);
            }
        }
    }
        
    ImGui::EndChild();

#if 0
    if(ImGui::Button("OK", ImVec2(120, 0)))
    {
        Gui->ModalFuncShow = 0x0;
    } ImGui::SetItemDefaultFocus(); ImGui::SameLine();
    
    if(ImGui::Button("Cancel", ImVec2(120, 0)))
    {
        Gui->ModalFuncShow = 0x0;
    }
#endif

    ImGui::End();
}

static void
GuiShowOpenFile()
{
    Gui->ModalFuncShow = _ImGuiShowOpenFileModalWindow;
}

static void
GuiSetStatusText(char *Str)
{
    Gui->StatusText = StringDuplicate(&Gui->Arena, Str);
}

static void
GuiClearStatusText()
{
    Gui->StatusText = 0x0;
}

#define TEX_WIDTH 16
#define TEX_HEIGHT 16
#define PNG_CHANNEL 4
    
static void
GuiCreateBreakpointTexture()
{
    u8 ImageBuffer[TEX_HEIGHT * TEX_WIDTH * PNG_CHANNEL] = {};

    for(int y = 0; y < TEX_HEIGHT; y++)
    {
        for(int x = 0; x < TEX_WIDTH; x++)
        {
            u8 Color = 0;

            f32 MidY = TEX_WIDTH * 0.5f;
            f32 MidX = TEX_HEIGHT * 0.5f;
            f32 OffX = (f32)x - MidY;
            f32 OffY = (f32)y - MidX;
            if(OffX * OffX + OffY * OffY < MidY*MidY*0.65f)
            {
                Color = 255;
            }

            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 0] = Color;
            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 1] = 0;
            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 2] = 0;
            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 3] = Color;
        }
    }

    GLuint BPTexture = 0;
    glGenTextures(1, &BPTexture);
    glBindTexture(GL_TEXTURE_2D, BPTexture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE); 
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, TEX_WIDTH, TEX_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, ImageBuffer);

    for(int y = 0; y < TEX_HEIGHT; y++)
    {
        for(int x = 0; x < TEX_WIDTH; x++)
        {
            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 0] = 0;
            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 1] = 0;
            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 2] = 0;
            ImageBuffer[y * TEX_WIDTH * PNG_CHANNEL + (x * PNG_CHANNEL) + 3] = 0;
        }
    }
    
    GLuint BPBlankTexture = 0;
    glGenTextures(1, &BPBlankTexture);
    glBindTexture(GL_TEXTURE_2D, BPBlankTexture);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE); 
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, TEX_WIDTH, TEX_HEIGHT, 0, GL_RGBA, GL_UNSIGNED_BYTE, ImageBuffer);

    Gui->BreakpointTextureActive = (void *)(uintptr_t)BPTexture;
    Gui->BreakpointTextureBlank  = (void *)(uintptr_t)BPBlankTexture;
}

static void
GuiBuildFunctionRepresentation()
{
    assert(Gui->FuncRepresentation == 0x0);

    Gui->FuncRepresentation = (function_representation *)malloc(sizeof(Gui->FuncRepresentation[0]) * DI->FunctionsCount);
    Gui->FuncRepresentationCount = 0;
    
    for(u32 I = 0; I < DI->FunctionsCount; I++)
    {
        di_function *Func = &DI->Functions[I];
        function_representation Repr = {};
        Repr.Label = DwarfGetFunctionStringRepresentation(Func);
        Repr.ActualFunction = Func;
        Gui->FuncRepresentation[Gui->FuncRepresentationCount++] = Repr;
    }
}

static void
GuiShowBacktrace()
{
    if(Debugee.Flags.Running)
    {
        size_t PC = DebugeeGetProgramCounter();

        // We know our cache is stale
        if(Debuger.Unwind.Address != PC)
        {
            DebugeeBuildBacktrace();
        }

        u32 Cnt = 1;
        for(unwind_functions_bucket *Bucket = Debuger.Unwind.FuncList.Head; Bucket != 0x0; Bucket = Bucket->Next)
        {
            for(u32 I = 0; I < Bucket->Count; I++)
            {
                unwind_function Function = Bucket->Functions[I];

                ImGui::Text("%02d: %s", Cnt++, Function->Label);
            }
        }
    }
}

static char *
idontknowyet(di_underlaying_type *Underlaying, size_t Address, arena *Arena)
{
    char *Result = ArrayPush(Arena, char, 64);

    if(Underlaying->Flags.IsBase && !Underlaying->Flags.IsArray)
    {
        size_t InMemory = DebugeePeekMemory(Address);
        union types_ptrs
        {
            void *Void;
            float *Float;
            double *Double;
            char *Char;
            short *Short;
            int *Int;
            long long *Long;
        } TypesPtrs;
        TypesPtrs.Void = &InMemory;

        if(Underlaying->Flags.IsPointer)
        {
            // String
            if(Underlaying->Type->Encoding == DW_ATE_signed_char && Underlaying->PointerCount == 1)
            {
            }
            else
            {
                sprintf(Result, "%p", (void *)(*TypesPtrs.Long));
            }
        }
        else
        {
            switch(Underlaying->Type->ByteSize)
            {
            case 1:
            {
                if(Underlaying->Type->Encoding == DW_ATE_signed_char)
                {
                    sprintf(Result, "%c (%x)", *TypesPtrs.Char, *TypesPtrs.Char);
                }
                else
                {
                    sprintf(Result, "%u", (unsigned int)*TypesPtrs.Char);
                }
            }
            break;
            case 2:
            {
                if(Underlaying->Type->Encoding == DW_ATE_signed)
                {
                    sprintf(Result, "%d", *TypesPtrs.Short);
                }
                else
                {
                    sprintf(Result, "%u", (unsigned int)*TypesPtrs.Short);
                }
            }
            break;
            case 4:
            {
                if(Underlaying->Type->Encoding == DW_ATE_unsigned)
                {
                    sprintf(Result, "%u", (unsigned int)*TypesPtrs.Int);
                }
                else if(Underlaying->Type->Encoding == DW_ATE_float)
                {
                    sprintf(Result, "%f", *TypesPtrs.Float);
                }
                else
                {
                    sprintf(Result, "%d", *TypesPtrs.Int);
                }
            }
            break;
            case 8:
            {
                if(Underlaying->Type->Encoding == DW_ATE_unsigned)
                {
                    sprintf(Result, "%llu", (unsigned long long)*TypesPtrs.Long);
                }
                else if(Underlaying->Type->Encoding == DW_ATE_float)
                {
                    sprintf(Result, "%f", *TypesPtrs.Double);
                }
                else
                {
                    sprintf(Result, "%lld", *TypesPtrs.Long);
                }
            }
            break;
            default:
            {
                LOG_GUI("Unsupported byte size = %d", Underlaying->Type->ByteSize);
            }
            break;
            }
        }
    }
    else if((Underlaying->Flags.IsStruct || Underlaying->Flags.IsUnion) && !Underlaying->Flags.IsArray)
    {
        if(Underlaying->Flags.IsPointer)
        {
            size_t InMemory = DebugeePeekMemory(Address);
            void *Ptr = (void *)InMemory;

            sprintf(Result, "0x%p", Ptr);
        }
        else
        {
            sprintf(Result, "{...}");
        }
    }
    else if(Underlaying->Flags.IsArray)
    {
        sprintf(Result, "[...]");
    }
    else
    {
        assert(false);
    }

    return Result;
}

static variable_representation
GuiBuildVariableRepresentation(di_variable *Var, arena *Arena)
{
    variable_representation Result = {};

    Result.Underlaying = DwarfFindUnderlayingType(Var->TypeOffset);

    Result.Type = Result.Underlaying.Flags;
    Result.ActualVariable = Var;
    Result.Name = Var->Name;

    Result.Address = DwarfGetVariableMemoryAddress(Var);
    Result.ValueString = idontknowyet(&Result.Underlaying, Result.Address, Arena);
    
    // @Memleak
    Result.TypeString = DwarfGetTypeStringRepresentation(Result.Underlaying, Arena);

    return Result;
}

static variable_representation
GuiBuildMemberRepresentation(size_t TypeOffset, size_t Address, char *Name, arena *Arena)
{
    variable_representation Result = {};

    Result.Underlaying = DwarfFindUnderlayingType(TypeOffset);

    Result.Type = Result.Underlaying.Flags;
    Result.ActualVariable = 0x0;
    Result.Name = Name;

    Result.Address = Address;
    Result.ValueString = idontknowyet(&Result.Underlaying, Result.Address, Arena);
    
    // @Memleak
    Result.TypeString = DwarfGetTypeStringRepresentation(Result.Underlaying, Arena);

    return Result;
}

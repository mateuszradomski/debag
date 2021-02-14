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
GuiShowVariable(variable_representation *Variable, arena *Arena)
{
    if(Variable->Underlaying.Flags.IsBase && !Variable->Underlaying.Flags.IsArray)
    {
        ImGui::Text(Variable->Name); ImGui::NextColumn();

        if(Variable->IsEdited)
        {
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0.0f, 0.0f));
            ImGui::InputText("###input_label", Gui->VariableEditBuffer, sizeof(Gui->VariableEditBuffer));
            ImGui::PopStyleVar();

            if(KeyboardButtons[GLFW_KEY_ENTER].Pressed)
            {
                size_t ToPoke = 0x0;

                u8 *ParsedBytes = (u8 *)&ToPoke;
                di_underlaying_type *Underlaying = &Variable->Underlaying;
                char *String = Gui->VariableEditBuffer;
                
                u32 TypeBytesCnt = DwarfParseTypeStringToBytes(Underlaying, String, ParsedBytes);

                if(TypeBytesCnt < sizeof(size_t))
                {
                    size_t InMemoryAlready = DebugeePeekMemory(Variable->Address);
                    u8 *MemoryBytes = (u8 *)&InMemoryAlready;

                    for(u32 I = TypeBytesCnt; I < sizeof(size_t); I++)
                    {
                        ParsedBytes[I] = MemoryBytes[I];
                    }
                }

                DebugeePokeMemory(Variable->Address, ToPoke);

                Variable[0] = GuiRebuildVariableRepresentation(Variable, Arena);
            }

            if(KeyboardButtons[GLFW_KEY_ESCAPE].Pressed || KeyboardButtons[GLFW_KEY_ENTER].Pressed)
            {
                Variable->IsEdited = false;
                memset(Gui->VariableEditBuffer, 0, sizeof(Gui->VariableEditBuffer));
            }
        }
        else
        {
            ImGui::Text(Variable->ValueString);
        } ImGui::NextColumn();

        bool Change = ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && ImGui::IsItemClicked();
        if(Change)
        {
            Variable->IsEdited = true;
        }

        ImGui::Text(Variable->TypeString); ImGui::NextColumn();
    }
    else if((Variable->Underlaying.Flags.IsStruct || Variable->Underlaying.Flags.IsUnion) && !Variable->Underlaying.Flags.IsArray)
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
                Variable->ChildrenCount = Struct->MembersCount;

                Variable->Children = ArrayPush(Arena, variable_representation, Variable->ChildrenCount);

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
    else if(Variable->Underlaying.Flags.IsArray)
    {
        bool Open = ImGui::TreeNode(Variable->Name); ImGui::NextColumn();
        ImGui::Text(Variable->ValueString); ImGui::NextColumn();
        ImGui::Text(Variable->TypeString); ImGui::NextColumn();

        if(Open)
        {
            if(!Variable->Children)
            {
                Variable->ChildrenCount = Variable->Underlaying.ArrayUpperBound + 1;
                Variable->Children = ArrayPush(Arena, variable_representation, Variable->ChildrenCount);

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
    if(Gui->BuildAddress != PC)
    {
        ArenaClear(&Gui->RepresentationArena);
        Gui->BuildAddress = PC;
        
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

        Gui->Variables = ArrayPush(&Gui->RepresentationArena, variable_representation, ToAllocate);
        Gui->VariableCnt = 0;

        for(u32 I = 0; CU && I < CU->GlobalVariablesCount; I++)
        {
            di_variable *Var = &CU->GlobalVariables[I];
            if(Var->LocationAtom)
            {
                Gui->Variables[Gui->VariableCnt++] = GuiBuildVariableRepresentation(Var, &Gui->RepresentationArena);
            }
        }

        if(Func && Func->FrameBaseIsCFA)
        {
            for(u32 I = 0; I < Func->ParamCount; I++)
            {
                di_variable *Param = &Func->Params[I];
                Gui->Variables[Gui->VariableCnt++] = GuiBuildVariableRepresentation(Param, &Gui->RepresentationArena);
            }

            for(u32 I = 0; I < Func->FuncLexScope.VariablesCount; I++)
            {
                di_variable *Var = &Func->FuncLexScope.Variables[I];
                Gui->Variables[Gui->VariableCnt++] = GuiBuildVariableRepresentation(Var, &Gui->RepresentationArena);
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
                        Gui->Variables[Gui->VariableCnt++] = GuiBuildVariableRepresentation(Var, &Gui->RepresentationArena);
                    }
                }
            }
        }
        else if(Func)
        {
            assert(false);
        }
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

    for(u32 I = 0; I < Gui->VariableCnt; I++)
    {
        GuiShowVariable(&Gui->Variables[I], &Gui->RepresentationArena);
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
        bool FuncHasName = Repr->ActualFunction->Name != 0x0;
        if(FuncHasName)
        {
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
    u32 ResultSize = 64;
    char *Result = ArrayPush(Arena, char, ResultSize);

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
                if(InMemory)
                {
                    size_t StringPart = DebugeePeekMemory(InMemory);
                    char *CharHead = (char *)&StringPart;
                    
                    u32 WrittenToString = 0;
                    Result[WrittenToString++] = '\"';
                    
                    u32 RemainingBytes = sizeof(StringPart);
                    while(CharHead[0] && IS_PRINTABLE(CharHead[0]))
                    {
                        if(WrittenToString == ResultSize - 6)
                        {
                            assert(RemainingBytes);

                            for(u32 I = 0; I < 3; I++) { Result[WrittenToString++] = '.'; };
                            break;
                        }

                        Result[WrittenToString++] = CharHead[0];
                        CharHead += 1;
                        RemainingBytes -= 1;

                        if(!RemainingBytes)
                        {
                            RemainingBytes = sizeof(StringPart);
                            InMemory += sizeof(StringPart);
                
                            StringPart = DebugeePeekMemory(InMemory);
                            CharHead = (char *)&StringPart;
                        }
                    }
                    
                    Result[WrittenToString++] = '\"';
                }
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

            sprintf(Result, "%p", Ptr);
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
        sprintf(Result, "Unknown thingee");
    }

    return Result;
}

static variable_representation
GuiRebuildVariableRepresentation(variable_representation *Var, arena *Arena)
{
    if(Var->ActualVariable)
    {
        return GuiBuildVariableRepresentation(Var->ActualVariable, Arena);
    }
    else
    {
        size_t TypeOffset = Var->Underlaying.Type->DIEOffset;
        size_t Address = Var->Address;

        return GuiBuildMemberRepresentation(TypeOffset, Address, Var->Name, Arena);
    }
}

static variable_representation
GuiBuildVariableRepresentation(di_variable *Var, arena *Arena)
{
    variable_representation Result = {};

    Result.Underlaying = DwarfFindUnderlayingType(Var->TypeOffset);

    Result.ActualVariable = Var;
    Result.Name = Var->Name;

    Result.Address = DwarfGetVariableMemoryAddress(Var);
    Result.ValueString = idontknowyet(&Result.Underlaying, Result.Address, Arena);
    
    Result.TypeString = DwarfGetTypeStringRepresentation(Result.Underlaying, Arena);

    return Result;
}

static variable_representation
GuiBuildMemberRepresentation(size_t TypeOffset, size_t Address, char *Name, arena *Arena)
{
    variable_representation Result = {};

    Result.Underlaying = DwarfFindUnderlayingType(TypeOffset);

    Result.ActualVariable = 0x0;
    Result.Name = Name;

    Result.Address = Address;
    Result.ValueString = idontknowyet(&Result.Underlaying, Result.Address, Arena);
    
    Result.TypeString = DwarfGetTypeStringRepresentation(Result.Underlaying, Arena);

    return Result;
}

static void
ImGuiStartFrame()
{
    ImGui_ImplOpenGL2_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
}

static void
ImGuiEndFrame()
{
    ImGui::Render();
    ImGui_ImplOpenGL2_RenderDrawData(ImGui::GetDrawData());
}

static void
ImGuiShowRegisters(x64_registers Regs)
{
    ImGui::Columns(4, 0x0, true);
    
    // NOTE(mateusz): We ignore we registers that are the last 10 in the 'x64_registers' struct
    u32 IgnoreCount = 10;
    
    for(u32 I = 0; I < (sizeof(Regs) / sizeof(size_t)) - IgnoreCount; I++)
    {
        ImGui::Text("%s : %lX", GetRegisterNameByIndex(I), Regs.Array[I]);
        ImGui::NextColumn();
    }
    
    ImGui::Columns(1);
}

static void
ImGuiShowValueAsString(size_t DereferencedAddress)
{
    char Temp[256] = {};
    u32 TIndex = 0;
    
    Temp[TIndex++] = '\"';
    if(DereferencedAddress)
    {
        size_t MachineWord = PeekDebugeeMemory(DereferencedAddress, Debuger.DebugeePID);
        char *PChar = (char *)&MachineWord;
        
        int RemainingBytes = sizeof(MachineWord);
        while(PChar[0] && IS_PRINTABLE(PChar[0]))
        {
            Temp[TIndex++] = PChar[0];
            PChar += 1;
            
            RemainingBytes -= 1;
            if(RemainingBytes == 0)
            {
                RemainingBytes = sizeof(MachineWord);
                DereferencedAddress += sizeof(MachineWord);
                
                MachineWord = PeekDebugeeMemory(DereferencedAddress, Debuger.DebugeePID);
                PChar = (char *)&MachineWord;
            }
        }
    }
    Temp[TIndex++] = '\"';
    assert(TIndex < sizeof(Temp));
    
    char AddrTemp[24] = {};
    sprintf(AddrTemp, " (%p)", (void *)DereferencedAddress);
    
    for(u32 I = 0; I < sizeof(AddrTemp); I++)
    {
        Temp[TIndex++] = AddrTemp[I];
    }
    assert(TIndex < sizeof(Temp));
    
    ImGui::Text("%s", Temp);
}

static void
ImGuiShowBaseType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    di_base_type *BType = Underlaying.Type;
    size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
    
    ImGui::Text("%s", VarName);
    ImGui::NextColumn();
    
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
    TypesPtrs.Void = &MachineWord;
    
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        if(BType->Encoding == DW_ATE_signed_char && Underlaying.PointerCount == 1)
        {
            size_t DereferencedAddress = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
            ImGuiShowValueAsString(DereferencedAddress);
        }
        else
        {
            ImGui::Text("%p", TypesPtrs.Void);
        }
    }
    else
    {
        switch(BType->ByteSize)
        {
            case 1:
            {
                if(BType->Encoding == DW_ATE_signed_char)
                {
                    ImGui::Text("%c (%x)", *TypesPtrs.Char, (*TypesPtrs.Char));
                }
                else
                {
                    ImGui::Text("%u", (unsigned int)*TypesPtrs.Char);
                }
            }break;
            case 2:
            {
                if(BType->Encoding == DW_ATE_signed)
                {
                    ImGui::Text("%d", *TypesPtrs.Short);
                }
                else
                {
                    ImGui::Text("%u", (unsigned int)*TypesPtrs.Short);
                }
            }break;
            case 4:
            {
                if(BType->Encoding == DW_ATE_unsigned)
                {
                    ImGui::Text("%u", (unsigned int)*TypesPtrs.Int);
                }
                else if(BType->Encoding == DW_ATE_float)
                {
                    ImGui::Text("%f", *TypesPtrs.Float);
                }
                else
                {
                    ImGui::Text("%d", *TypesPtrs.Int);
                }
            }break;
            case 8:
            {
                if(BType->Encoding == DW_ATE_unsigned)
                {
                    ImGui::Text("%llu", (unsigned long long)*TypesPtrs.Long);
                }
                else if(BType->Encoding == DW_ATE_float)
                {
                    ImGui::Text("%f", *TypesPtrs.Double);
                }
                else
                {
                    ImGui::Text("%lld", *TypesPtrs.Long);
                }
            }break;
            default:
            {
                printf("Unsupported byte size = %d", BType->ByteSize);
            }break;
        }
    }
    
    char TypeName[128] = {};
    strcat(TypeName, Underlaying.Name);
    
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        strcat(TypeName, " *");
    }
    
    ImGui::NextColumn();
    ImGui::Text("%s", TypeName);
    ImGui::NextColumn();
}

static void
ImGuiShowStructType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    di_struct_type *Struct = Underlaying.Struct;
    size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
    
    char TypeName[128] = {};
    StringConcat(TypeName, Underlaying.Name);
    
    // TODO(mateusz): Stacked pointers dereference, like (void **)
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        VarAddress = MachineWord;
        
        strcat(TypeName, " *");
    }
    
    // Anonymous union
    if(StringEmpty(VarName))
    {
        for(u32 MemberIndex = 0; MemberIndex < Struct->MembersCount; MemberIndex++)
        {
            di_struct_member *Member = &Struct->Members[MemberIndex];
            size_t MemberAddress = VarAddress + Member->ByteLocation;
            assert(Member->Name);
            
            ImGuiShowVariable(Member->ActualTypeOffset, MemberAddress, Member->Name);
        }
    }
    else
    {
        bool Open = ImGui::TreeNode(VarName, "%s", VarName);
        ImGui::NextColumn();
        ImGui::Text("0x%lx", VarAddress);
        ImGui::NextColumn();
        ImGui::Text("%s", TypeName);
        ImGui::NextColumn();
        
        if(Open)
        {
            for(u32 MemberIndex = 0; MemberIndex < Struct->MembersCount; MemberIndex++)
            {
                di_struct_member *Member = &Struct->Members[MemberIndex];
                size_t MemberAddress = VarAddress + Member->ByteLocation;
                assert(Member->Name);
                
                ImGuiShowVariable(Member->ActualTypeOffset, MemberAddress, Member->Name);
            }
            
            ImGui::TreePop();
        }
    }
    
}

static void
ImGuiShowArrayType(di_underlaying_type Underlaying, size_t VarAddress, char *VarName)
{
    char TypeName[128] = {};
    strcat(TypeName, Underlaying.Name);
    size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
    
    // TODO(mateusz): Stacked pointers dereference, like (void **)
    if(Underlaying.Flags & TYPE_IS_POINTER)
    {
        VarAddress = MachineWord;
        
        strcat(TypeName, " *");
    }
    
    bool Open = ImGui::TreeNode(VarName, "%s", VarName);
    ImGui::NextColumn();
    if(Underlaying.Type->Encoding == DW_ATE_signed_char)
    {
        ImGuiShowValueAsString(VarAddress);
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
            //size_t MachineWord = PeekDebugeeMemory(VarAddress, Debuger.DebugeePID);
            
            if(Underlaying.Flags & TYPE_IS_STRUCT || Underlaying.Flags & TYPE_IS_UNION)
            {
                char VarNameWI[128] = {};
                sprintf(VarNameWI, "%s[%d]", VarName, I);
                
                ImGuiShowStructType(Underlaying, VarAddress, VarNameWI);
                
                VarAddress += Underlaying.Struct->ByteSize;
            }
            else if(Underlaying.Flags & TYPE_IS_BASE)
            {
                char VarNameWI[128] = {};
                sprintf(VarNameWI, "%s[%d]", VarName, I);
                
                ImGuiShowBaseType(Underlaying, VarAddress, VarNameWI);
                
                VarAddress += Underlaying.Type->ByteSize;
            }
            else
            {
                //printf("Var [%s] doesn't have a type\n", VarName);
                //assert(false);
            }
        }
        ImGui::TreePop();
    }
}

static void
ImGuiShowVariable(size_t TypeOffset, size_t VarAddress, char *VarName = "")
{
    di_underlaying_type Underlaying = FindUnderlayingType(TypeOffset);
    
    if(Underlaying.Flags & TYPE_IS_ARRAY)
    {
        ImGuiShowArrayType(Underlaying, VarAddress, VarName);
    }
    else if(Underlaying.Flags & TYPE_IS_STRUCT || Underlaying.Flags & TYPE_IS_UNION)
    {
        // NOTE(mateusz): We are treating unions and struct as the same thing, but with ByteLocation = 0
        assert(sizeof(di_union_type) == sizeof(di_struct_type));
        assert(sizeof(di_union_member) == sizeof(di_struct_member));
        
        ImGuiShowStructType(Underlaying, VarAddress, VarName);
    }
    else if(Underlaying.Flags & TYPE_IS_BASE)
    {
        ImGuiShowBaseType(Underlaying, VarAddress, VarName);
    }
    else
    {
        //printf("Var [%s] doesn't have a type\n", VarName);
        //assert(false);
    }
}

static void
ImGuiShowVariable(di_variable *Var, size_t FBReg)
{
    // TODO(mateusz): Other ways of accessing variables
    if(Var->LocationAtom == DW_OP_fbreg)
    {
        size_t VarAddress = FBReg + Var->Offset;
        ImGuiShowVariable(Var->TypeOffset, VarAddress, Var->Name);
    }
}

static void
_ImGuiShowBreakAtFunctionModalWindow()
{
    char *FuncBreakLabel = "Function to break at"; 
    
    if(ImGui::BeginPopupModal(FuncBreakLabel))
    {
        ImGui::Text("Enter the function name you wish to set a brekpoint");
        ImGui::Separator();
        
        ImGui::InputText("Name", Gui->BreakFuncName, sizeof(Gui->BreakFuncName));
        
        if(ImGui::Button("OK", ImVec2(120, 0)))
        {
            BreakAtFunctionName(Gui->BreakFuncName);
            UpdateInfo();
            
            ImGui::CloseCurrentPopup(); 
            memset(Gui->BreakFuncName, 0, sizeof(Gui->BreakFuncName));
            Gui->ModalFuncShow = 0x0;
        }
        ImGui::SetItemDefaultFocus();
        
        ImGui::SameLine();
        if(ImGui::Button("Cancel", ImVec2(120, 0)))
        {
            ImGui::CloseCurrentPopup();
            memset(Gui->BreakFuncName, 0, sizeof(Gui->BreakFuncName));
            Gui->ModalFuncShow = 0x0;
        }
        ImGui::EndPopup();
    }
}

static void
ImGuiShowBreakAtFunction()
{
    char *FuncBreakLabel = "Function to break at"; 
    
    ImGui::OpenPopup(FuncBreakLabel);
    ImVec2 Center(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(Center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    Gui->ModalFuncShow = _ImGuiShowBreakAtFunctionModalWindow;
}

static void 
_ImGuiShowBreakAtAddressModalWindow()
{
    char *AddressBreakLabel = "Address to break at";
    
    if(ImGui::BeginPopupModal(AddressBreakLabel))
    {
        ImGui::Text("Enter the address you wish to set a brekpoint, hex or decimal");
        ImGui::Separator();
        
        ImGui::InputText("Address", Gui->BreakAddress, sizeof(Gui->BreakAddress));
        
        if(ImGui::Button("OK", ImVec2(120, 0)))
        {
            BreakAtAddress(Gui->BreakAddress);
            UpdateInfo();
            
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
ImGuiShowBreakAtAddress()
{
    char *AddressBreakLabel = "Address to break at";
    ImGui::OpenPopup(AddressBreakLabel);
    ImVec2 Center(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f);
    ImGui::SetNextWindowPos(Center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    
    Gui->ModalFuncShow = _ImGuiShowBreakAtAddressModalWindow;
}

static void
GuiSetStatusText(char *Str)
{
    Gui->StatusText = StringDuplicate(Gui->Arena, Str);
}

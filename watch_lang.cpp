static char *
LexerTokenKindToString(token_kind Kind)
{
	switch(Kind)
	{
		case TokenKind_Symbol:
		return "TokenKind_Symbol";
	    case TokenKind_BracketOp:
	    return "TokenKind_BracketOp";
	    case TokenKind_BracketCl:
	    return "TokenKind_BracketCl";
    	case TokenKind_ParenOp:
    	return "TokenKind_ParenOp";
    	case TokenKind_ParenCl:
    	return "TokenKind_ParenCl";
    	case TokenKind_ImmInt:
    	return "TokenKind_ImmInt";
    	case TokenKind_Arrow:
    	return "TokenKind_Arrow";
    	case TokenKind_Dot:
    	return "TokenKind_Dot";
    	case TokenKind_Star:
    	return "TokenKind_Star";
    	case TokenKind_DotDot:
    	return "TokenKind_DotDot";
    	case TokenKind_EOF:
    	return "TokenKind_EOF";
    	default:
    	return "Unknown token kind";
	}
}

static void
LexerLogTokens(lexer *Lexer)
{
	LOG_LANG("There are %d toknes\n", Lexer->Tokens.Count);

	for(lex_token_node *TokenNode = Lexer->Tokens.Head;
		TokenNode != 0x0;
		TokenNode = TokenNode->Next)
	{
		lex_token *Token = &TokenNode->Token;

		if(Token->Content)
		{
			LOG_LANG("%s [%s]\n", LexerTokenKindToString(Token->Kind), Token->Content);
		}
		else
		{
			LOG_LANG("%s\n", LexerTokenKindToString(Token->Kind));
		}
	}
}

static lexer
LexerCreate(char *Content, arena *Arena)
{
	lexer Result = {};

	Result.Arena = Arena;
	Result.Content = Content;

	return Result;
}

static void
LexerDestroy(lexer *Lexer)
{
	(void)Lexer;
}

static char
LexerPeekChar(lexer *Lexer)
{
	char Result = '\0';

	assert(Lexer);
	if(Lexer->Content && Lexer->Content[Lexer->ContentPos])
	{
		Result = Lexer->Content[Lexer->ContentPos];
	}

	return Result;
}

static char
LexerConsumeChar(lexer *Lexer)
{
	char Result = '\0';

	assert(Lexer);
	if(Lexer->Content && Lexer->Content[Lexer->ContentPos])
	{
		Result = Lexer->Content[Lexer->ContentPos];
		Lexer->ContentPos += 1;
	}

	return Result;
}

static void
LexerPushToken(lexer *Lexer, lex_token Token)
{
	lex_token_node *Node = ArrayPush(Lexer->Arena, lex_token_node, 1);
	Node->Token = Token;
	SLL_QUEUE_PUSH(Lexer->Tokens.Head, Lexer->Tokens.Tail, Node);
	Lexer->Tokens.Count += 1;
}

static void
LexerBuildTokens(lexer *Lexer)
{
	char C = '\0';

	bool Minus = false;

	while((C = LexerConsumeChar(Lexer)))
	{
		if(isdigit(C))
		{
			u32 BytesLeft = 16;
			char *String = ArrayPush(Lexer->Arena, char, BytesLeft);
			u32 StringPos = 0;

			if(Minus)
			{
				Minus = false;
				String[StringPos++] = C;
				BytesLeft--;
			}

			String[StringPos++] = C;
			BytesLeft--;

			while((C = LexerPeekChar(Lexer)))
			{
				if(isdigit(C))
				{
					if(!BytesLeft)
					{
						BytesPush(Lexer->Arena, 16);
						BytesLeft = 16;
					}

					String[StringPos++] = C;
					BytesLeft--;

					LexerConsumeChar(Lexer);
				}
				else
				{
					break;
				}
			}

			lex_token Token = {};
			Token.Kind = TokenKind_ImmInt;
			Token.Content = String;
			LexerPushToken(Lexer, Token);
		}
		else if(C == '[')
		{
			lex_token Token = {};
			Token.Kind = TokenKind_BracketOp;
			LexerPushToken(Lexer, Token);
		}
		else if(C == ']')
		{
			lex_token Token = {};
			Token.Kind = TokenKind_BracketCl;
			LexerPushToken(Lexer, Token);
		}
		else if(C == '(')
		{			
			lex_token Token = {};
			Token.Kind = TokenKind_ParenOp;
			LexerPushToken(Lexer, Token);
		}
		else if(C == ')')
		{
			lex_token Token = {};
			Token.Kind = TokenKind_ParenCl;
			LexerPushToken(Lexer, Token);	
		}
		else if(C == '-')
		{
			Minus = true;			
		}
		else if(C == '>')
		{
            if(!Minus)
            {
                Lexer->ErrorStr = ArrayPush(Lexer->Arena, char, sizeof("Unexpected character (%c)\n"));
                sprintf(Lexer->ErrorStr, "Unexpected character (%c)\n", C);
                return;
            }
                
			Minus = false;

			lex_token Token = {};
			Token.Kind = TokenKind_Arrow;
			LexerPushToken(Lexer, Token);
		}
		else if(C == '.')
		{
			lex_token Token = {};

			char C2 = LexerPeekChar(Lexer);
			if(C2 == '.')
			{
				LexerConsumeChar(Lexer);
				Token.Kind = TokenKind_DotDot;
			}
			else
			{
				Token.Kind = TokenKind_Dot;
			}

			LexerPushToken(Lexer, Token);
		}
		else if(C == '*')
		{
			lex_token Token = {};
			Token.Kind = TokenKind_Star;
			LexerPushToken(Lexer, Token);
		}
		else if(C == '_' || isalpha(C))
		{
			u32 BytesLeft = 16;
			char *String = ArrayPush(Lexer->Arena, char, BytesLeft);
			u32 StringPos = 0;

			String[StringPos++] = C;
			BytesLeft--;

			while((C = LexerPeekChar(Lexer)))
			{
				if(C == '_' || isalpha(C) || isdigit(C))
				{
					if(!BytesLeft)
					{
						BytesPush(Lexer->Arena, 16);
						BytesLeft = 16;
					}

					String[StringPos++] = C;
					BytesLeft--;

					LexerConsumeChar(Lexer);
				}
				else
				{
					break;
				}
			}

			lex_token Token = {};
			Token.Kind = TokenKind_Symbol;
			Token.Content = String;
			LexerPushToken(Lexer, Token);
		}
		else
		{
            Lexer->ErrorStr = ArrayPush(Lexer->Arena, char, sizeof("Unexpected character (%c)\n"));
            sprintf(Lexer->ErrorStr, "Unexpected character (%c)\n", C);
            return;
		}
	}

	lex_token Token = {};
	Token.Kind = TokenKind_EOF;
	LexerPushToken(Lexer, Token);
}

static char *
ParserASTNodeKindToString(ast_node_kind Kind)
{
    switch(Kind)
    {
    case ASTNodeKind_None:
        return "ASTNodeKind_None";
    case ASTNodeKind_Expr:
        return "ASTNodeKind_Expr";
    case ASTNodeKind_IntLit:
        return "ASTNodeKind_IntLit";
    case ASTNodeKind_Ident:
        return "ASTNodeKind_Ident";
    case ASTNodeKind_IndexExpr:
        return "ASTNodeKind_IndexExpr";
    case ASTNodeKind_DotAccess:
        return "ASTNodeKind_DotAccess";
    case ASTNodeKind_ArrowAccess:
        return "ASTNodeKind_ArrowAccess";
    case ASTNodeKind_PtrDeref:
        return "ASTNodeKind_PtrDeref";
    default:
        return "Unexpected ASTNodeKind";
    }
}

static parser
ParserCreate(lex_token_list *Tokens, arena *Arena)
{
	parser Result = {};

	Result.Tokens = Tokens;
	Result.Arena = Arena;

	return Result;
}

static void	
ParserDestroy(parser *Parser)
{
	(void)Parser;
}

static lex_token *
ParserPeekToken(parser *Parser)
{
	return &Parser->PosNode->Token;
}

static lex_token *
ParserConsumeToken(parser *Parser)
{
	lex_token *Result = 0x0;

	if(!Parser->PosNode)
	{
		Parser->PosNode = Parser->Tokens->Head;
		Result = &Parser->PosNode->Token;
	}
	else
	{
		Parser->PosNode = Parser->PosNode->Next;
		Result = &Parser->PosNode->Token;
	}

	return Result;
}

static ast_node *
ParserNextExpression(parser *Parser, ast_node *Prev, token_kind Delimiter)
{
    if(Parser->ErrorStr)
    {
        return 0x0;
    }

    lex_token *Token = ParserConsumeToken(Parser);
    if(!Token)
    {
        Parser->ErrorStr = "Unexpected end of file.";
        return 0x0;
    }

    if(Token->Kind == Delimiter)
    {
        return Prev;
    }

    if(!Prev)
    {
        if(Token->Kind == TokenKind_Symbol)
        {
            ast_node *Node = StructPush(Parser->Arena, ast_node);
            Node->Kind = ASTNodeKind_Ident;
            Node->Token = Token;

            return ParserNextExpression(Parser, Node, Delimiter);
        }
        else if(Token->Kind == TokenKind_ImmInt)
        {
            ast_node *Node = StructPush(Parser->Arena, ast_node);
            Node->Kind = ASTNodeKind_IntLit;
            Node->Token = Token;

            return ParserNextExpression(Parser, Node, Delimiter);
        }
        else if(Token->Kind == TokenKind_Star)
        {
            ast_node *Node = StructPush(Parser->Arena, ast_node);
            Node->Kind = ASTNodeKind_PtrDeref;
            Node->Token = Token;

            Node->Rhs = StructPush(Parser->Arena, ast_node);
            Node->Rhs = ParserNextExpression(Parser, 0x0, Delimiter);

            if(Parser->PosNode->Token.Kind != Delimiter)
            {
                return ParserNextExpression(Parser, Node, Delimiter);
            }
            else
            {
                return Node;
            }
        }
        else if(Token->Kind == TokenKind_ParenOp)
        {
            token_kind NewDelimiter = TokenKind_ParenCl;
            ast_node *InsideParens = ParserNextExpression(Parser, 0x0, NewDelimiter);

            return ParserNextExpression(Parser, InsideParens, Delimiter);
        }
        else
        {
            Parser->ErrorStr = ArrayPush(Parser->Arena, char, 256);
            sprintf(Parser->ErrorStr, "Unexpected token %s %s\n", LexerTokenKindToString(Token->Kind), Token->Content);
            return 0x0;
        }
    }
    else
    {
        if(Token->Kind == TokenKind_BracketOp)
        {
            ast_node *IndexingExpr = ParserNextExpression(Parser, 0x0, TokenKind_BracketCl);

            ast_node *Node = StructPush(Parser->Arena, ast_node);
            Node->Kind = ASTNodeKind_IndexExpr;

            Node->Lhs = StructPush(Parser->Arena, ast_node);
            Node->Rhs = StructPush(Parser->Arena, ast_node);

            Node->Lhs = Prev;
            Node->Rhs = IndexingExpr;

            return ParserNextExpression(Parser, Node, Delimiter);
        }
        else if(Token->Kind == TokenKind_Dot)
        {
            lex_token *Token2 = ParserConsumeToken(Parser);

            if(Token2->Kind != TokenKind_Symbol)
            {
                Parser->ErrorStr = ArrayPush(Parser->Arena, char, 256);
                sprintf(Parser->ErrorStr, "Unexpected token %s %s\n", LexerTokenKindToString(Token->Kind), Token->Content);
                return 0x0;
            }

            ast_node *IdentNode = StructPush(Parser->Arena, ast_node);
            IdentNode->Kind = ASTNodeKind_Ident;
            IdentNode->Token = Token2;

            ast_node *Node = StructPush(Parser->Arena, ast_node);
            Node->Kind = ASTNodeKind_DotAccess;

            Node->Lhs = StructPush(Parser->Arena, ast_node);
            Node->Rhs = StructPush(Parser->Arena, ast_node);

            Node->Lhs = Prev;
            Node->Rhs = IdentNode;

            return ParserNextExpression(Parser, Node, Delimiter);
        }
        else if(Token->Kind == TokenKind_Arrow)
        {
            lex_token *Token2 = ParserConsumeToken(Parser);
            if(Token2->Kind != TokenKind_Symbol)
            {
                Parser->ErrorStr = ArrayPush(Parser->Arena, char, 256);
                sprintf(Parser->ErrorStr, "Unexpected token %s %s\n", LexerTokenKindToString(Token->Kind), Token->Content);
                return 0x0;
            }

            ast_node *IdentNode = StructPush(Parser->Arena, ast_node);
            IdentNode->Kind = ASTNodeKind_Ident;
            IdentNode->Token = Token2;

            ast_node *Node = StructPush(Parser->Arena, ast_node);
            Node->Kind = ASTNodeKind_ArrowAccess;

            Node->Lhs = StructPush(Parser->Arena, ast_node);
            Node->Rhs = StructPush(Parser->Arena, ast_node);

            Node->Lhs = Prev;
            Node->Rhs = IdentNode;

            return ParserNextExpression(Parser, Node, Delimiter);
        }
        else
        {
            Parser->ErrorStr = ArrayPush(Parser->Arena, char, 256);
            sprintf(Parser->ErrorStr, "Unexpected token %s %s\n", LexerTokenKindToString(Token->Kind), Token->Content);
            return 0x0;
        }
    }

    return 0x0;
}

static void
ParserBuildAST(parser *Parser)
{
    lex_token *FirstToken = ParserPeekToken(Parser);
    if(!FirstToken)
    {
        Parser->ErrorStr = "Unexpected end of file.";
        return;
    }

    ast_node *RootNode = ParserNextExpression(Parser, 0x0, TokenKind_EOF);
    if(RootNode)
    {
        Parser->AST.Root = RootNode;
    }
}

u32 LastArbNumber = 0;

static void
ParserCreateGraphvizFileFromAST(parser *Parser, char *OutputFilename)
{
	FILE *FileHandle = fopen(OutputFilename, "w");

	FILE_WRITE_STR("graph \"\"\n", FileHandle);
	FILE_WRITE_STR("{\n", FileHandle);

	FILE_WRITE_STR("subgraph main\n", FileHandle);
	FILE_WRITE_STR("{\n", FileHandle);

	ParserReasonAboutNode(Parser, FileHandle, Parser->AST.Root);

	FILE_WRITE_STR("}\n", FileHandle);

	FILE_WRITE_STR("}\n", FileHandle);

	fclose(FileHandle);
}

static void
ParserReasonAboutNode(parser *Parser, FILE *FileHandle, ast_node *Node, u32 PrevArb)
{
	u32 MyArbNumber = ++LastArbNumber;
	char ScratchString[256] = {};

	if(Node == Parser->AST.Root)
	{
		u32 Written = sprintf(ScratchString, "n%d ;\n", MyArbNumber);
		fwrite(ScratchString, Written, 1, FileHandle);
	}
	else
	{
		u32 Written = sprintf(ScratchString, "n%d -- n%d ;\n", PrevArb, MyArbNumber);
		fwrite(ScratchString, Written, 1, FileHandle);
	}

	char ScratchString2[128] = {};
	char *NodeKindStr = ParserASTNodeKindToString(Node->Kind);
	if(Node->Token && Node->Token->Content)
	{
		sprintf(ScratchString2, "%s (%s)", NodeKindStr, Node->Token->Content);
	}
	else
	{
		sprintf(ScratchString2, "%s", NodeKindStr);
	}

	u32 Written = sprintf(ScratchString, "n%d [label=\"%s\"]", MyArbNumber, ScratchString2);
	fwrite(ScratchString, Written, 1, FileHandle);

    if(Node->Lhs)
    {
		ParserReasonAboutNode(Parser, FileHandle, Node->Lhs, MyArbNumber);
    }
    if(Node->Rhs)
    {
		ParserReasonAboutNode(Parser, FileHandle, Node->Rhs, MyArbNumber);
    }
}

static char *
ExpressionResultKindToString(eval_result_kind Kind)
{
    switch(Kind)
    {
    case EvalResultKind_NumberInt:
        return "EvalResultKind_NumberInt";
    case EvalResultKind_Ident:
        return "EvalResultKind_Ident";
    case EvalResultKind_Repr:
        return "EvalResultKind_Repr";
    default:
        return "Unexpected expression kind";
    }
}

static evaluator
EvaluatorCreate(ast AST, scoped_vars Scope, arena *Arena)
{
    evaluator Result = {};

    Result.Scope = Scope;
    Result.Arena = Arena;
    Result.AST = AST;

    return Result;
}

static void
EvaluatorDestroy(evaluator *Eval)
{
    (void)Eval;
}

static eval_result
EvaluatorEvalExpression(evaluator *Eval, ast_node *Expr)
{
    if(Eval->ErrorStr)
    {
        return {};
    }

    if(!Expr)
    {
        Eval->ErrorStr = (char *)"Unexpected lack of expression";
        return {};
    }

    if(Expr->Kind == ASTNodeKind_IndexExpr)
    {
        if(!(Expr->Lhs && Expr->Rhs))
        {
            Eval->ErrorStr = (char *)"Unexpected lack of AST node children";
            return {};
        }

        eval_result LeftSide = EvaluatorEvalExpression(Eval, Expr->Lhs);
        eval_result RightSide = EvaluatorEvalExpression(Eval, Expr->Rhs);

        if(!(LeftSide.Kind == EvalResultKind_Ident || LeftSide.Kind == EvalResultKind_Repr))
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            sprintf(Eval->ErrorStr, "Unexpected expression kind %s\n", ExpressionResultKindToString(LeftSide.Kind));

            return {};
        }

        size_t VarAddress = 0x0;
        size_t TypeSize = 0x0;
        size_t TypeOffset = 0x0;
        char *VarName = 0x0;

        di_underlaying_type Underlaying = {};
        if(LeftSide.Kind == EvalResultKind_Ident)
        {
            di_variable *Var = DwarfFindVariableByNameInScope(Eval->Scope, LeftSide.Ident);
            if(!Var)
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Variable [%s] not found in current scope\n", LeftSide.Ident);

                return {};
            }
            
            VarAddress = DwarfGetVariableMemoryAddress(Var);
            VarName = Var->Name;
            Underlaying = DwarfFindUnderlayingType(Var->TypeOffset);
        }
        else if(LeftSide.Kind == EvalResultKind_Repr)
        {
            auto VarRepr = LeftSide.Repr;
            assert(VarRepr);

            VarAddress = VarRepr->Address;
            VarName = VarRepr->Name;
            Underlaying = VarRepr->Underlaying;
        }

        static_assert((offsetof(di_base_type, ByteSize) == offsetof(di_struct_type, ByteSize)) &&
                      (offsetof(di_base_type, ByteSize) == offsetof(di_union_type, ByteSize)),
                      "ByteSize arguments need to have the same offset between the checked types");
        // This is true only if the above assert passes 
        VarAddress = Underlaying.Flags.IsPointer ? DebugeePeekMemory(VarAddress) : VarAddress;
        TypeSize = Underlaying.Type->ByteSize;
        TypeOffset = Underlaying.Type->DIEOffset;

        if(!(RightSide.Kind == EvalResultKind_Ident ||
           RightSide.Kind == EvalResultKind_NumberInt ||
           RightSide.Kind == EvalResultKind_Repr))
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            sprintf(Eval->ErrorStr, "Cannot index with %s with %s ast node kind\n", RightSide.Ident, ExpressionResultKindToString(RightSide.Kind));

            return {};
        }

        i64 Index = 0;
        if(RightSide.Kind == EvalResultKind_Ident)
        {
            di_variable *Var = DwarfFindVariableByNameInScope(Eval->Scope, RightSide.Ident);
            if(!Var)
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Variable [%s] not found in current scope\n", RightSide.Ident);

                return {};
            }
            
            scratch_arena Scratch;
            variable_representation Repr = GuiBuildVariableRepresentation(Var, 0, Scratch);
            if(!(Repr.Underlaying.Flags.IsBase && Repr.Underlaying.Type->Encoding != DW_ATE_float))
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Cannot index with (%s) that is a non int type\n", RightSide.Ident);

                return {};
            }

            Index = atoll(Repr.ValueString);
        }
        else if(RightSide.Kind == EvalResultKind_NumberInt)
        {
            Index = RightSide.Int;
        }
        else if(RightSide.Kind == EvalResultKind_Repr)
        {
            Index = atoll(RightSide.Repr->ValueString);
        }

        size_t ResultAddress = VarAddress + Index * TypeSize;

        eval_result Result = {};
        size_t Address = ResultAddress;

        Result.Kind = EvalResultKind_Repr;
        Result.Repr = StructPush(Eval->Arena, variable_representation);
        (*Result.Repr) = GuiBuildVariableRepresentation(TypeOffset, Address, VarName, 0, Eval->Arena);

        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_DotAccess || Expr->Kind == ASTNodeKind_ArrowAccess)
    {
        if(!(Expr->Lhs && Expr->Rhs))
        {
            Eval->ErrorStr = (char *)"Unexpected lack of AST node children";
            return {};
        }

        eval_result LeftSide = EvaluatorEvalExpression(Eval, Expr->Lhs);
        eval_result RightSide = EvaluatorEvalExpression(Eval, Expr->Rhs);

        if(RightSide.Kind != EvalResultKind_Ident)
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            sprintf(Eval->ErrorStr, "Cannot access a struct/union member with %s ast node kind.", ExpressionResultKindToString(RightSide.Kind));
            return {};
        }

        if(!(LeftSide.Kind == EvalResultKind_Repr || LeftSide.Kind == EvalResultKind_Ident))
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            sprintf(Eval->ErrorStr, "Cannot access %s ast node kind as a struct/union.", ExpressionResultKindToString(LeftSide.Kind));
            return {};
        }

        size_t VarAddress = 0x0;
        size_t ByteLocation = 0x0;
        size_t TypeOffset = 0x0;

        di_underlaying_type Underlaying = {};
        if(LeftSide.Kind == EvalResultKind_Repr)
        {
            auto VarRepr = LeftSide.Repr;
            assert(VarRepr);
            
            if(!(VarRepr->Underlaying.Flags.IsStruct || VarRepr->Underlaying.Flags.IsUnion))
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Variable [%s] is not a struct/union type.", VarRepr->Name);
                return {};
            }

            VarAddress = VarRepr->Address;
            Underlaying = VarRepr->Underlaying;
        }
        else if(LeftSide.Kind == EvalResultKind_Ident)
        {
            di_variable *Var = DwarfFindVariableByNameInScope(Eval->Scope, LeftSide.Ident);
            if(!Var)
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Variable [%s] not found in current scope\n", LeftSide.Ident);

                return {};
            }

            VarAddress = DwarfGetVariableMemoryAddress(Var);
            Underlaying = DwarfFindUnderlayingType(Var->TypeOffset);
        }

        if(Underlaying.Flags.IsStruct)
        {
            di_struct_member *Member = DwarfStructGetMemberByName(Underlaying.Struct, RightSide.Ident);
            if(!Member)
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Struct [%s] does not contain [%s] as a member\n", Underlaying.Name, RightSide.Ident);

                return {};
            }

            ByteLocation = Member->ByteLocation;
            TypeOffset = Member->ActualTypeOffset;
        }
        else if(Underlaying.Flags.IsUnion)
        {
            di_union_member *Member = DwarfUnionGetMemberByName(Underlaying.Union, RightSide.Ident);
            if(!Member)
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Union [%s] does not contain [%s] as a member\n", Underlaying.Name, RightSide.Ident);

                return {};
            }

            ByteLocation = Member->ByteLocation;
            TypeOffset = Member->ActualTypeOffset;
        }

        eval_result Result = {};

        if(Expr->Kind == ASTNodeKind_ArrowAccess)
        {
            VarAddress = DebugeePeekMemory(VarAddress);
        }

        size_t Address = VarAddress + ByteLocation;
        Result.Kind = EvalResultKind_Repr;
        Result.Repr = StructPush(Eval->Arena, variable_representation);
        (*Result.Repr) = GuiBuildVariableRepresentation(TypeOffset, Address, StringDuplicate(Eval->Arena, RightSide.Ident), 0, Eval->Arena);

        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_PtrDeref)
    {
        if(!Expr->Rhs)
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            sprintf(Eval->ErrorStr, "Unexpected lack of right node child in pointer deref\n");

            return {};
        }

        eval_result RightSide = EvaluatorEvalExpression(Eval, Expr->Rhs);
        if(RightSide.Kind != EvalResultKind_Ident && RightSide.Kind != EvalResultKind_Repr)
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            char *KindStr = ExpressionResultKindToString(RightSide.Kind);
            sprintf(Eval->ErrorStr, "Cannot dereference [%s] eval kind result\n", KindStr);

            return {};
        }

        size_t VarAddress = 0x0;
        size_t TypeOffset = 0x0;
        di_underlaying_type Underlaying = {};
        char *VarName = 0x0;

        if(RightSide.Kind == EvalResultKind_Repr)
        {
            auto VarRepr = RightSide.Repr;
            assert(VarRepr);

            VarName = VarRepr->Name;
            VarAddress = VarRepr->Address;
            Underlaying = VarRepr->Underlaying;
        }
        else if(RightSide.Kind == EvalResultKind_Ident)
        {
            di_variable *Var = DwarfFindVariableByNameInScope(Eval->Scope, RightSide.Ident);
            if(!Var)
            {
                Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
                sprintf(Eval->ErrorStr, "Variable [%s] not found in current scope\n", RightSide.Ident);

                return {};
            }

            VarName = Var->Name;
            VarAddress = DwarfGetVariableMemoryAddress(Var);
            Underlaying = DwarfFindUnderlayingType(Var->TypeOffset);
        }

        if(!Underlaying.Flags.IsPointer)
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            sprintf(Eval->ErrorStr, "Variable [%s] is not a pointer type.", VarName);
            return {};
        }

        TypeOffset = Underlaying.Type->DIEOffset;
        
        eval_result Result = {};
        Result.Kind = EvalResultKind_Repr;
        Result.Repr = StructPush(Eval->Arena, variable_representation);
        (*Result.Repr) = GuiBuildVariableRepresentation(TypeOffset, VarAddress, StringDuplicate(Eval->Arena, RightSide.Ident), 1, Eval->Arena);
        Result.Repr->DerefCount = 1;

        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_Ident)
    {
        assert(Expr->Token && Expr->Token->Content);
        char *Ident = Expr->Token->Content;

        eval_result Result = {};
        Result.Kind = EvalResultKind_Ident;
        Result.Ident = Ident;

        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_IntLit)
    {
        eval_result Result = {};
        Result.Kind = EvalResultKind_NumberInt;
        Result.Int = atoi(Expr->Token->Content);

        return Result;
    }
    else
    {
        printf("Unexpected AST Kind = %s\n", ParserASTNodeKindToString(Expr->Kind));
        assert(false);
    }
}

static void
EvaluatorRun(evaluator *Eval)
{
    eval_result EvalResult = EvaluatorEvalExpression(Eval, Eval->AST.Root);

    if(Eval->ErrorStr)
    {
        return;
    }
    
    if(EvalResult.Kind == EvalResultKind_Ident)
    {
        di_variable *Var = DwarfFindVariableByNameInScope(Eval->Scope, EvalResult.Ident);
        if(!Var)
        {
            Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
            sprintf(Eval->ErrorStr, "Variable [%s] not found in current scope\n", EvalResult.Ident);

            return;
        }

        Eval->Result = StructPush(Eval->Arena, variable_representation);
        (*Eval->Result) = GuiBuildVariableRepresentation(Var, 0, Eval->Arena);
    }
    else if(EvalResult.Kind == EvalResultKind_Repr)
    {
        Eval->Result = EvalResult.Repr;
    }
    else
    {
        Eval->ErrorStr = ArrayPush(Eval->Arena, char, 256);
        sprintf(Eval->ErrorStr, "Can't convert [%s] result kind to a showable representation\n", ExpressionResultKindToString(EvalResult.Kind));

        return;
    }
}

static wlang_interp
WLangInterpCreate(char *Src, scoped_vars Scope)
{
	wlang_interp Result = {};

	Result.Arena = ArenaCreate(Kilobytes(4));
	Result.Src = StringDuplicate(&Result.Arena, Src);
    Result.Scope = Scope;

	return Result;
}

static void
WLangInterpDestroy(wlang_interp *Interp)
{
	LexerDestroy(&Interp->Lexer);
	ParserDestroy(&Interp->Parser);
	EvaluatorDestroy(&Interp->Eval);

	ArenaDestroy(&Interp->Arena);
}

static void
WLangInterpRun(wlang_interp *Interp)
{
	Interp->Lexer = LexerCreate(Interp->Src, &Interp->Arena);
	LexerBuildTokens(&Interp->Lexer);
    if(Interp->Lexer.ErrorStr)
    {
        LOG_LANG("[Lexer Error]: %s\n", Interp->Lexer.ErrorStr);
        Interp->ErrorStr = Interp->Lexer.ErrorStr;
        return;
    }

	LexerLogTokens(&Interp->Lexer);

	Interp->Parser = ParserCreate(&Interp->Lexer.Tokens, &Interp->Arena);
	ParserBuildAST(&Interp->Parser);
    if(Interp->Parser.ErrorStr)
    {
        LOG_LANG("[Parser Error]: %s\n", Interp->Parser.ErrorStr);
        Interp->ErrorStr = Interp->Parser.ErrorStr;
        return;
    }

	Interp->Eval = EvaluatorCreate(Interp->Parser.AST, Interp->Scope, &Interp->Arena);
	EvaluatorRun(&Interp->Eval);
    
    if(Interp->Eval.ErrorStr)
    {
        LOG_LANG("[Evaluator Error]: %s\n", Interp->Eval.ErrorStr);
        Interp->ErrorStr = Interp->Eval.ErrorStr;
        return;
    }

	Interp->Result = Interp->Eval.Result;
}

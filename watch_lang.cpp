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
			Token.Kind = TokenKind_ParenOp;
			LexerPushToken(Lexer, Token);	
		}
		else if(C == '-')
		{
			Minus = true;			
		}
		else if(C == '>')
		{
			assert(Minus);
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
			assert(false && "Unreachable code");
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
	lex_token *Token = ParserConsumeToken(Parser);
	assert(Token);
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
        else
        {
			printf("Unexpected token %s %s\n", LexerTokenKindToString(Token->Kind), Token->Content);
            assert(false);
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
            assert(Token2->Kind == TokenKind_Symbol);

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
            assert(Token2->Kind == TokenKind_Symbol);

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
			printf("Unexpected token %s %s\n", LexerTokenKindToString(Token->Kind), Token->Content);
			assert(false);
		}
	}

	return 0x0;
}

static void
ParserBuildAST(parser *Parser)
{
	assert(ParserPeekToken(Parser));

	Parser->AST.Root = ParserNextExpression(Parser, 0x0, TokenKind_EOF);
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

static evaluator
EvaluatorCreate(ast AST, variable_representation *Vars, u32 VarCount)
{
    evaluator Result = {};

    Result.Vars = Vars;
    Result.VarCount = VarCount;
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
    if(Expr->Kind == ASTNodeKind_IndexExpr)
    {
        assert(Expr->Lhs && Expr->Rhs);

        eval_result LeftSide = EvaluatorEvalExpression(Eval, Expr->Lhs);
        eval_result RightSide = EvaluatorEvalExpression(Eval, Expr->Rhs);

        auto VarRepr = LeftSide.Repr;

        static_assert((offsetof(di_base_type, ByteSize) == offsetof(di_struct_type, ByteSize)) &&
                      (offsetof(di_base_type, ByteSize) == offsetof(di_union_type, ByteSize)),
                      "ByteSize arguments need to have the same offset between the checked types");
        // This is true only if the above assert passes 
        size_t TypeSize = VarRepr->Underlaying.Type->ByteSize;
        
        size_t BaseAddress = VarRepr->Underlaying.Flags.IsPointer ? DebugeePeekMemory(VarRepr->Address) : VarRepr->Address;
        
        i64 Index = 0;
        if(RightSide.Repr)
        {
            assert(RightSide.Repr->Underlaying.Flags.IsBase &&
                   RightSide.Repr->Underlaying.Type->Encoding != DW_ATE_float);

            Index = atoll(RightSide.Repr->ValueString);
        }
        else
        {
            Index = RightSide.Int;
        }

        size_t ResultAddress = BaseAddress + Index * TypeSize;

        eval_result Result = {};

        size_t TypeOffset = VarRepr->Underlaying.Type->DIEOffset;
        size_t Address = ResultAddress;

        // TODO(mateusz): No gui Arena
        Result.Repr = StructPush(&Gui->Arena, variable_representation);
        (*Result.Repr) = GuiBuildMemberRepresentation(TypeOffset, Address, VarRepr->Name, &Gui->Arena);

        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_DotAccess)
    {
        assert(Expr->Lhs && Expr->Rhs);

        eval_result LeftSide = EvaluatorEvalExpression(Eval, Expr->Lhs);
        eval_result RightSide = EvaluatorEvalExpression(Eval, Expr->Rhs);

        assert(RightSide.Ident);
        
        auto VarRepr = LeftSide.Repr;
        assert(VarRepr);
        assert(VarRepr->Underlaying.Flags.IsStruct || VarRepr->Underlaying.Flags.IsUnion);

        bool Found = false;
        size_t ByteLocation = 0x0;
        size_t TypeOffset = 0x0;
        if(VarRepr->Underlaying.Flags.IsStruct)
        {
            di_struct_type *Struct = VarRepr->Underlaying.Struct;
            for(u32 I = 0; I < Struct->MembersCount; I++)
            {
                if(StringMatches(RightSide.Ident, Struct->Members[I].Name))
                {
                    ByteLocation = Struct->Members[I].ByteLocation;
                    TypeOffset = Struct->Members[I].ActualTypeOffset;
                    Found = true;
                    break;
                }
            }
        }

        assert(Found);

        eval_result Result = {};

        size_t Address = VarRepr->Address + ByteLocation;
        Result.Repr = StructPush(&Gui->Arena, variable_representation);
        (*Result.Repr) = GuiBuildMemberRepresentation(TypeOffset, Address, StringDuplicate(&Gui->Arena, RightSide.Ident), &Gui->Arena);
        
        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_ArrowAccess)
    {
        assert(Expr->Lhs && Expr->Rhs);

        eval_result LeftSide = EvaluatorEvalExpression(Eval, Expr->Lhs);
        eval_result RightSide = EvaluatorEvalExpression(Eval, Expr->Rhs);

        assert(RightSide.Ident);

        auto VarRepr = LeftSide.Repr;
        assert(VarRepr);
        assert(VarRepr->Underlaying.Flags.IsStruct || VarRepr->Underlaying.Flags.IsUnion);

        bool Found = false;
        size_t ByteLocation = 0x0;
        size_t TypeOffset = 0x0;
        if(VarRepr->Underlaying.Flags.IsStruct)
        {
            di_struct_type *Struct = VarRepr->Underlaying.Struct;
            for(u32 I = 0; I < Struct->MembersCount; I++)
            {
                if(StringMatches(RightSide.Ident, Struct->Members[I].Name))
                {
                    ByteLocation = Struct->Members[I].ByteLocation;
                    TypeOffset = Struct->Members[I].ActualTypeOffset;
                    Found = true;
                    break;
                }
            }
        }

        assert(Found);

        eval_result Result = {};

        size_t VarAddress = DebugeePeekMemory(VarRepr->Address);

        size_t Address = VarAddress + ByteLocation;
        Result.Repr = StructPush(&Gui->Arena, variable_representation);
        (*Result.Repr) = GuiBuildMemberRepresentation(TypeOffset, Address, StringDuplicate(&Gui->Arena, RightSide.Ident), &Gui->Arena);

        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_Ident)
    {
        assert(Expr->Token && Expr->Token->Content);
        char *Ident = Expr->Token->Content;
        
        eval_result Result = {};
        variable_representation *VarRepr = 0x0;
        for(u32 I = 0; I < Eval->VarCount; I++)
        {
            variable_representation *Current = &Eval->Vars[I];
            if(StringMatches(Ident, Current->Name))
            {
                VarRepr = Current;
                break;
            }
        }

        if(VarRepr)
        {
            Result.Repr = VarRepr;
        }
        else
        {
            Result.Ident = Ident;
        }

        return Result;
    }
    else if(Expr->Kind == ASTNodeKind_IntLit)
    {
        eval_result Result = {};
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

    Eval->Result = EvalResult.Repr;
}

static wlang_interp
WLangInterpCreate(char *Src, variable_representation *Vars, u32 VarCount)
{
	wlang_interp Result = {};

	Result.Arena = ArenaCreate(Kilobytes(4));
	Result.Src = StringDuplicate(&Result.Arena, Src);
	Result.Vars = Vars;
	Result.VarCount = VarCount;

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

	LexerLogTokens(&Interp->Lexer);

	Interp->Parser = ParserCreate(&Interp->Lexer.Tokens, &Interp->Arena);
	ParserBuildAST(&Interp->Parser);

	Interp->Eval = EvaluatorCreate(Interp->Parser.AST, Interp->Vars, Interp->VarCount);
	EvaluatorRun(&Interp->Eval);
	Interp->Result = Interp->Eval.Result;
}

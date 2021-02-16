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
    	default:
    	return "Unknown token kind";
	}
}

static lexer
LexerCreate(char *Content)
{
	lexer Result = {};

	Result.Arena = ArenaCreateZeros(Kilobytes(4));
	Result.Content = StringDuplicate(&Result.Arena, Content);

	return Result;
}

static void
LexerDestroy(lexer *Lexer)
{
	ArenaDestroy(&Lexer->Arena);
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
	lex_token_node *Node = ArrayPush(&Lexer->Arena, lex_token_node, 1);
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
			char *String = ArrayPush(&Lexer->Arena, char, BytesLeft);
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
						BytesPush(&Lexer->Arena, 16);
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
			Token.Kind = TokenKind_Dot;
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
			char *String = ArrayPush(&Lexer->Arena, char, BytesLeft);
			u32 StringPos = 0;

			String[StringPos++] = C;
			BytesLeft--;

			while((C = LexerPeekChar(Lexer)))
			{
				if(C == '_' || isalpha(C))
				{
					if(!BytesLeft)
					{
						BytesPush(&Lexer->Arena, 16);
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
}

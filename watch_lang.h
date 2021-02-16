/* date = February 16th 2021 11:55 am */

#ifndef WATCH_LANG_H
#define WATCH_LANG_H

enum
{
	TokenKind_Symbol,
    TokenKind_BracketOp,
    TokenKind_BracketCl,
    TokenKind_ParenOp,
    TokenKind_ParenCl,
    TokenKind_ImmInt,
    TokenKind_Arrow,
    TokenKind_Dot,
    TokenKind_Star,
};

typedef u32 token_kind;

struct lex_token
{
	token_kind Kind;
	char *Content;
};

struct lex_token_node
{
	lex_token_node *Next;
	lex_token Token;
};

struct lex_token_list
{
	lex_token_node *Head;
	lex_token_node *Tail;
	u32 Count;
};

struct lexer
{
	arena Arena;
	char *Content;
	u32 ContentPos;
	lex_token_list Tokens;
};

static char *	LexerTokenKindToString(token_kind Kind);

static lexer 	LexerCreate(char *Content);
static void 	LexerDestroy(lexer *Lexer);
static char 	LexerPeekChar(lexer *Lexer);
static char 	LexerConsumeChar(lexer *Lexer);
static void 	LexerBuildTokens(lexer *Lexer);

#endif //WATCH_LANG_H
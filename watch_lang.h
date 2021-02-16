/* date = February 16th 2021 11:55 am */

#ifndef WATCH_LANG_H
#define WATCH_LANG_H

enum
{
	TokenKind_None,
	TokenKind_Symbol,
    TokenKind_BracketOp,
    TokenKind_BracketCl,
    TokenKind_ParenOp,
    TokenKind_ParenCl,
    TokenKind_ImmInt,
    TokenKind_Arrow,
    TokenKind_Dot,
    TokenKind_Star,
    TokenKind_DotDot,
    TokenKind_EOF,
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

enum 
{
	ASTNodeKind_None,
	ASTNodeKind_Expr,
	ASTNodeKind_IntLit,
	ASTNodeKind_Ident,
	ASTNodeKind_IndexExpr,
};

typedef u32 ast_node_kind;

struct ast_node
{
	ast_node_kind Kind;
	lex_token *Token;
	ast_node **Children;
	u32 ChildrenCount;
};

struct ast
{
	ast_node *Root;
};

struct parser
{
	arena Arena;

	lex_token_list *Tokens;
	lex_token_node *PosNode;
	ast AST;
};

#define FILE_WRITE_STR(str, file) (fwrite(str, sizeof(str) - 1, 1, file))

static char *	LexerTokenKindToString(token_kind Kind);

static lexer 	LexerCreate(char *Content);
static void 	LexerDestroy(lexer *Lexer);
static char 	LexerPeekChar(lexer *Lexer);
static char 	LexerConsumeChar(lexer *Lexer);
static void 	LexerBuildTokens(lexer *Lexer);

static char * 		ParserASTNodeKindToString(ast_node_kind Kind);

static parser		ParserCreate(lex_token_list *Tokens);
static void			ParserDestroy(parser *Parser);
static lex_token *	ParserPeekToken(parser *Parser);
static lex_token *	ParserConsumeToken(parser *Parser);
static ast_node *	ParserNextExpression(parser *Parser, ast_node *Prev, token_kind Delimiter);
static void 		ParserBuildAST(parser *Parser);
static void 		ParserCreateGraphvizFileFromAST(parser *Parser, char *OutputFilename);
static void			ParserReasonAboutNode(parser *Parser, FILE *FileHandle, ast_node *Node, u32 PrevArb = 0);

#endif //WATCH_LANG_H
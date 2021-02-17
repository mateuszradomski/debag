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
	arena *Arena;
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
    ASTNodeKind_DotAccess,
    ASTNodeKind_ArrowAccess,
};

typedef u32 ast_node_kind;

struct ast_node
{
	ast_node_kind Kind;
	lex_token *Token;
    ast_node *Rhs;
    ast_node *Lhs;
};

struct ast
{
	ast_node *Root;
};

struct parser
{
	arena *Arena;
	lex_token_list *Tokens;
	lex_token_node *PosNode;
	ast AST;
};

enum
{
    EvalResultKind_NumberInt,
    EvalResultKind_Ident,
    EvalResultKind_Repr,
};

typedef u32 eval_result_kind;

struct eval_result
{
    eval_result_kind Kind;
    i64 Int;
    char *Ident;
    variable_representation *Repr;
};

struct evaluator
{
    variable_representation *Result;
    scoped_vars Scope;
    ast AST;
};

struct wlang_interp
{
	arena Arena;
	lexer Lexer;
	parser Parser;
	evaluator Eval;

	char *Src;
    scoped_vars Scope;
	variable_representation *Vars;
    u32 VarCount;

    variable_representation *Result;
};

#define FILE_WRITE_STR(str, file) (fwrite(str, sizeof(str) - 1, 1, file))

#ifdef DEBUG
#define LOG_LANG(fmt, ...) if(Debuger.Log.LangLogs) { printf(fmt, ##__VA_ARGS__); }
#else
#define LOG_LANG(...) do { } while (0)
#endif

static char *	LexerTokenKindToString(token_kind Kind);
static void 	LexerLogTokens(lexer *Lexer);

static lexer 	LexerCreate(char *Content, arena *Arena);
static void 	LexerDestroy(lexer *Lexer);
static char 	LexerPeekChar(lexer *Lexer);
static char 	LexerConsumeChar(lexer *Lexer);
static void 	LexerBuildTokens(lexer *Lexer);


static char * 		ParserASTNodeKindToString(ast_node_kind Kind);

static parser		ParserCreate(lex_token_list *Tokens, arena *Arena);
static void			ParserDestroy(parser *Parser);
static lex_token *	ParserPeekToken(parser *Parser);
static lex_token *	ParserConsumeToken(parser *Parser);
static ast_node *	ParserNextExpression(parser *Parser, ast_node *Prev, token_kind Delimiter);
static void 		ParserBuildAST(parser *Parser);
static void 		ParserCreateGraphvizFileFromAST(parser *Parser, char *OutputFilename);
static void			ParserReasonAboutNode(parser *Parser, FILE *FileHandle, ast_node *Node, u32 PrevArb = 0);

static evaluator    EvaluatorCreate(ast AST, scoped_vars Scope);
static void         EvaluatorDestroy(evaluator *Eval);
static eval_result	EvaluatorEvalExpression(evaluator *Eval, ast_node *Expr);
static void    		EvaluatorRun(evaluator *Eval);

static wlang_interp	WLangInterpCreate(char *Src, scoped_vars Scope, variable_representation *Vars, u32 VarCount);
static void 		WLangInterpDestroy(wlang_interp *Interp);
static void			WLangInterpRun(wlang_interp *Interp);

#endif //WATCH_LANG_H

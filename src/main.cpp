#include <debag.cpp>

int
main(i32 ArgCount, char **Args)
{
    if(ArgCount == 2)
    {
        if(StringMatches(Args[1], "-wl"))
        {
            scratch_arena Scratch;
            char *WatchLangSrc = (char *)"(*myArray).x";

            lexer Lexer = LexerCreate(WatchLangSrc, Scratch);
            LexerBuildTokens(&Lexer);

            printf("There are %d tokens\n", Lexer.Tokens.Count);

            for(lex_token_node *TokenNode = Lexer.Tokens.Head;
                TokenNode != 0x0;
                TokenNode = TokenNode->Next)
            {
                lex_token *Token = &TokenNode->Token;

                if(Token->Content)
                {
                    printf("%s [%s]\n", LexerTokenKindToString(Token->Kind), Token->Content);
                }
                else
                {
                    printf("%s\n", LexerTokenKindToString(Token->Kind));
                }
            }

            parser Parser = ParserCreate(&Lexer.Tokens, Scratch);
            ParserBuildAST(&Parser);

            ParserCreateGraphvizFileFromAST(&Parser, "graph_src.dot");

            ParserDestroy(&Parser);
            LexerDestroy(&Lexer);

            return 0;
        }

        StringCopy(Debugee.ProgramPath, Args[1]);
    }
    
    DebugerMain();
    
    return 0;
}

/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2024 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE

#include <ctype.h>
#include <string.h>
#include "hades.h"
#include "app/lang.h"

static
struct token *
token_new(
    struct lexer *lexer,
    int kind
) {
    struct token *t;

    t = malloc(sizeof(*t));
    hs_assert(t);

    memset(t, 0, sizeof(*t));
    t->kind = kind;
    t->next = NULL;

    if (lexer->last) {
        lexer->last->next = t;
    }

    lexer->last = t;

    if (!lexer->tokens) {
        lexer->tokens = t;
    }

    return (t);
}

static
struct token *
token_new_op(
    struct lexer *lexer,
    enum operator op
) {
    struct token *token;

    token = token_new(lexer, TOKEN_OPERATOR);
    token->value.operator = op;
    return (token);
}

void
debugger_lang_lexe(
    struct lexer *lexer,
    char const *input
) {
    size_t i;

    i = 0;
    while (input[i]) {
        switch (input[i]) {
            case '.':
            case '_':
            case 'a' ... 'z':
            case 'A' ... 'Z': {
                /* Lexe the whole identifier */
                struct token *t;
                size_t j;

                j = 0;
                while (isalnum(input[i + j]) || input[i + j] == '.' || input[i + j] == '_' || input[i + j] == '/') {
                    ++j;
                }

                if (j >= strlen("true") && !strncmp(input + i, "true", j)) {
                    t = token_new(lexer, TOKEN_LITTERAL);
                    t->value.litteral = 1;
                } else if (j >= strlen("false") && !strncmp(input + i, "false", j)) {
                    t = token_new(lexer, TOKEN_LITTERAL);
                    t->value.litteral = 0;
                } else {
                    t = token_new(lexer, TOKEN_IDENTIFIER);
                    t->value.identifier = strndup(input + i, j);
                }

                i += j;
                break;
            };
            case '0' ... '9': {
                /* Lexe the whole number */
                char *end;
                struct token *t;

                t = token_new(lexer, TOKEN_LITTERAL);
                if (input[i] == '0' && input[i + 1] == 'b') {
                    t->value.litteral = strtoull(input + i + 2, &end, 2);
                } else {
                    t->value.litteral = strtoull(input + i, &end, 0);
                }
                i += end - (input + i);
                if (isalpha(input[i])) {
                    lexer->error = hs_format("Invalid character \'%c\'", input[i]);
                    return ;
                }
                break;
            };
            case '+': {
                if (input[i + 1] == '=') {
                    token_new_op(lexer, OP_BINARY_ADDASSIGN);
                    ++i;
                } else {
                    token_new_op(lexer, OP_BINARY_ADD);
                }
                ++i;
                break;
            };
            case '-': {
                if (input[i + 1] == '=') {
                    token_new_op(lexer, OP_BINARY_SUBASSIGN);
                    ++i;
                } else {
                    token_new_op(lexer, OP_BINARY_SUB);
                }
                ++i;
                break;
            };
            case '*': {
                if (input[i + 1] == '=') {
                    token_new_op(lexer, OP_BINARY_MULASSIGN);
                    ++i;
                } else {
                    token_new_op(lexer, OP_BINARY_MUL);
                }
                ++i;
                break;
            };
            case '/': {
                if (input[i + 1] == '=') {
                    token_new_op(lexer, OP_BINARY_DIVASSIGN);
                    ++i;
                } else {
                    token_new_op(lexer, OP_BINARY_DIV);
                }
                ++i;
                break;
            };
            case '=': {
                token_new_op(lexer, OP_BINARY_ASSIGN);
                ++i;
                break;
            };
            case '(': {
                token_new(lexer, TOKEN_OPEN_PARENTHESIS);
                ++i;
                break;
            };
            case ')': {
                token_new(lexer, TOKEN_CLOSE_PARENTHESIS);
                ++i;
                break;
            };
            case ' ':
            case '\r':
            case '\n':
            case '\t': {
                ++i;
                break;
            };
            default: {
                lexer->error = hs_format("Invalid character \'%c\'", input[i]);
                return ;
            };
        }
    }
}

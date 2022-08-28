/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <stdio.h>
#include "hades.h"
#include "platform/gui/lang.h"

void
debugger_lang_dump_lexer(
    struct lexer const *lexer
) {
    struct token const *token;

    token = lexer->tokens;
    while (token) {
        printf("Token { ");
        switch (token->kind) {
            case TOKEN_LITTERAL: {
                printf("Litteral (%lli)", token->value.litteral);
                break;
            };
            case TOKEN_IDENTIFIER: {
                printf("Identifier (%s)", token->value.identifier);
                break;
            };
            case TOKEN_OPERATOR: {
                printf("Operator (\"%s\")", operator_name[token->value.operator]);
                break;
            };
            case TOKEN_OPEN_PARENTHESIS: {
                printf("Open Parenthesis");
                break;
            };
            case TOKEN_CLOSE_PARENTHESIS: {
                printf("Close Parenthesis");
                break;
            };
        }
        printf(" }\n");
        token = token->next;
    }
}

static
void
debugger_lang_dump_ast_indentation(
    size_t indentation
) {
    while (indentation) {
        printf("    ");
        --indentation;
    }
}

static
void
debugger_lang_dump_ast_raw(
    struct node const *node,
    size_t indent
) {
    switch (node->kind) {
        case NODE_LITTERAL: {
            printf("Node { Litteral (%lli) }\n", node->value.litteral);
            break;
        };
        case NODE_VARIABLE: {
            printf("Node { Variable (%s) }\n", node->value.identifier);
            break;
        };
        case NODE_OP_UNARY: {
            printf("Node {\n");

            debugger_lang_dump_ast_indentation(indent + 1);
            printf("Operator: %s (unary)\n", operator_name[node->value.operator]);

            debugger_lang_dump_ast_indentation(indent + 1);
            printf("RHS: ");
            debugger_lang_dump_ast_raw(node->rhs, indent + 1);

            debugger_lang_dump_ast_indentation(indent);
            printf("}\n");
            break;
        };
        case NODE_OP_BINARY: {
            printf("Node {\n");

            debugger_lang_dump_ast_indentation(indent + 1);
            printf("Operator: %s\n", operator_name[node->value.operator]);

            debugger_lang_dump_ast_indentation(indent + 1);
            printf("LHS: ");
            debugger_lang_dump_ast_raw(node->lhs, indent + 1);


            debugger_lang_dump_ast_indentation(indent + 1);
            printf("RHS: ");
            debugger_lang_dump_ast_raw(node->rhs, indent + 1);

            debugger_lang_dump_ast_indentation(indent);
            printf("}\n");
            break;
        };
    }
}

void
debugger_lang_dump_ast(
    struct ast const *ast
) {
    debugger_lang_dump_ast_raw(ast->root, 0);
}

static
void
debugger_lang_cleanup_node(
    struct node *node
) {
    if (!node) {
        return ;
    }

    switch (node->kind) {
        case NODE_VARIABLE: {
            free(node->value.identifier);
            break;
        };
        case NODE_OP_UNARY: {
            debugger_lang_cleanup_node(node->rhs);
            break;
        };
        case NODE_OP_BINARY: {
            debugger_lang_cleanup_node(node->lhs);
            debugger_lang_cleanup_node(node->rhs);
            break;
        };
        default: {
            break;
        }
    }
    free(node);
}

void
debugger_lang_cleanup(
    struct lexer *lexer,
    struct ast *ast,
    struct eval *eval
) {
    struct token *token;

    /* Lexer */

    token = lexer->tokens;
    while (token) {
        struct token *old_token;

        if (token->kind == TOKEN_IDENTIFIER) {
            free(token->value.identifier);
        }

        old_token = token;
        token = token->next;
        free(old_token);
    }
    free(lexer->error);
    lexer->last = NULL;
    lexer->tokens = NULL;
    lexer->error = NULL;

    /* Parser */

    debugger_lang_cleanup_node(ast->root);
    free(ast->error);
    ast->root = NULL;
    ast->error = NULL;

    /* Eval */
    free(eval->error);
    eval->error = NULL;
}
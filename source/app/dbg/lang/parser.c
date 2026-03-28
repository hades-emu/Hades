/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#define _GNU_SOURCE

#include <string.h>
#include "hades.h"
#include "app/lang.h"

static struct node *debugger_lang_parse_expr(struct ast *ast);

static
struct node *
node_new(
    int kind
) {
    struct node *t;

    t = malloc(sizeof(*t));
    hs_assert(t);

    memset(t, 0, sizeof(*t));
    t->kind = kind;

    return (t);
}

static
struct node *
debugger_lang_parse_value(
    struct ast *ast
) {
    struct token const *token;

    token = ast->token;
    if (!token) {
        return (NULL);
    }

    if (token->kind == TOKEN_OPERATOR && (token->value.operator == OP_BINARY_ADD || token->value.operator == OP_BINARY_SUB)) {
        struct node *op;

        op = node_new(NODE_OP_UNARY);
        op->value.operator = token->value.operator == OP_BINARY_ADD ? OP_UNARY_PLUS : OP_UNARY_MINUS;
        ast->token = token->next; // Eat '+'
        op->rhs = debugger_lang_parse_value(ast); // Parse rhs
        return (op);
    } else if (token->kind == TOKEN_LITTERAL) {
        struct node *node;

        node = node_new(NODE_LITTERAL);
        node->value.litteral = token->value.litteral;
        ast->token = token->next; // Eat litteral
        return (node);
    } else if (token->kind == TOKEN_OPEN_PARENTHESIS) {
        struct node *content;

        ast->token = token->next; // Eat '('
        content = debugger_lang_parse_expr(ast);
        token = ast->token;

        if (!content && token) {
            free(ast->error);
            ast->error = strdup("Parenthesis have no content");
            return (NULL);
        }

        if (!token || token->kind != TOKEN_CLOSE_PARENTHESIS) {
            free(ast->error);
            ast->error = strdup("Missing closing parenthesis");
            return (content);
        }

        ast->token = token->next; // Eat ')'
        return (content);
    } else if (token->kind == TOKEN_IDENTIFIER) {
        struct node *node;

        node = node_new(NODE_VARIABLE);
        node->value.identifier = strdup(token->value.identifier);
        ast->token = token->next; // Eat identifier
        return (node);
    }
    free(ast->error);
    ast->error = strdup("Invalid syntax");
    return (NULL);
}

static
struct node *
debugger_lang_try_parse_binary_op(
    struct ast *ast,
    int32_t prio,
    struct node *lhs
) {
    struct token const *token;

    token = ast->token;
    if (lhs
        && token
        && token->kind == TOKEN_OPERATOR
        && token->value.operator > _OP_BINARY_START_
        && token->value.operator < _OP_BINARY_END_
    ) {
        struct node *op;
        int32_t new_prio;

        new_prio = operator_binary_prio[token->value.operator];
        if (new_prio < prio) {
            return (lhs);
        }

        op = node_new(NODE_OP_BINARY);
        op->value.operator = token->value.operator;
        op->lhs = lhs;

        ast->token = token->next; // Eat operator
        if (!ast->token) {
            free(ast->error);
            ast->error = hs_format("Missing right-handside value for operator \"%s\"", operator_name[op->value.operator]);
            return (op);
        }

        op->rhs = debugger_lang_parse_value(ast); // Parse RHS
        if (!op->rhs) {
            return (NULL);
        }

        token = ast->token;
        if (token
            && token->kind == TOKEN_OPERATOR
            && token->value.operator > _OP_BINARY_START_
            && token->value.operator < _OP_BINARY_END_
        ) {
            int32_t next_prio;

            next_prio = operator_binary_prio[token->value.operator];
            if (new_prio < next_prio) {
                op->rhs = debugger_lang_try_parse_binary_op(ast, prio + 1, op->rhs);
            }
        }

        return (debugger_lang_try_parse_binary_op(ast, prio, op));
    }
    return (lhs);
}

static
struct node *
debugger_lang_parse_expr(
    struct ast *ast
) {
    return (debugger_lang_try_parse_binary_op(ast, 0, debugger_lang_parse_value(ast)));
}

void
debugger_lang_parse(
    struct ast *ast,
    struct token const *tokens
) {
    ast->token = tokens;
    ast->root = debugger_lang_parse_expr(ast);
}

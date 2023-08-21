
/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2023 - The Hades Authors
**
\******************************************************************************/

#pragma once

#ifdef WITH_DEBUGGER

#include <stdint.h>

struct variable {
    char const *name;
    bool mutable;
    union {
        uint32_t *ptr;  // Used if `mutable` is true
        uint32_t val;   // Used if `mutable` is false
    };
};

enum operator {
    _OP_UNARY_START_,
    OP_UNARY_PLUS,
    OP_UNARY_MINUS,
    _OP_UNARY_END_,

    _OP_BINARY_START_,
    _OP_BINARY_ASSIGN_START_,
    OP_BINARY_ASSIGN,
    OP_BINARY_ADDASSIGN,
    OP_BINARY_SUBASSIGN,
    OP_BINARY_MULASSIGN,
    OP_BINARY_DIVASSIGN,
    _OP_BINARY_ASSIGN_END_,
    OP_BINARY_ADD,
    OP_BINARY_SUB,
    OP_BINARY_MUL,
    OP_BINARY_DIV,
    _OP_BINARY_END_,
};

static int operator_binary_prio[] = {
    [OP_BINARY_ASSIGN]      = 10,
    [OP_BINARY_ADDASSIGN]   = 10,
    [OP_BINARY_SUBASSIGN]   = 10,
    [OP_BINARY_MULASSIGN]   = 10,
    [OP_BINARY_DIVASSIGN]   = 10,

    [OP_BINARY_ADD]         = 20,
    [OP_BINARY_SUB]         = 20,

    [OP_BINARY_MUL]         = 30,
    [OP_BINARY_DIV]         = 30,
};

static char *operator_name[] = {
    [OP_UNARY_PLUS]         = "+",
    [OP_UNARY_MINUS]        = "-",

    [OP_BINARY_ASSIGN]      = "=",
    [OP_BINARY_ADDASSIGN]   = "+=",
    [OP_BINARY_SUBASSIGN]   = "-=",
    [OP_BINARY_MULASSIGN]   = "*=",
    [OP_BINARY_DIVASSIGN]   = "/=",
    [OP_BINARY_ADD]         = "+",
    [OP_BINARY_SUB]         = "-",
    [OP_BINARY_MUL]         = "*",
    [OP_BINARY_DIV]         = "/",
};

struct token {
    enum {
        TOKEN_LITTERAL,
        TOKEN_IDENTIFIER,
        TOKEN_OPEN_PARENTHESIS,
        TOKEN_CLOSE_PARENTHESIS,
        TOKEN_OPERATOR,
    } kind;

    union {
        uint64_t litteral;
        char *identifier;
        enum operator operator;
    } value;

    struct token *next;
};

struct lexer {
    struct token *tokens;
    struct token *last;

    char *error;
};

struct node {
    enum {
        NODE_LITTERAL,
        NODE_OP_UNARY,
        NODE_OP_BINARY,
        NODE_VARIABLE,
    } kind;

    union {
        uint64_t litteral;
        char *identifier;
        enum operator operator;
    } value;

    struct node *lhs;  // For binary operators only
    struct node *rhs;  // For unary and binary operators only
};

struct ast {
    struct node *root;
    struct token const * token;
    char *error;
};

struct eval {
    char *error;
    int64_t res;
};

struct app;

/* debugger/lang/eval.c */
void debugger_lang_eval(struct eval *eval, struct app *app, struct ast const *ast);

/* debugger/lang/lexer.c */
void debugger_lang_lexe(struct lexer *lexer, char const *input);

/* debugger/lang/parser.c */
void debugger_lang_parse(struct ast *ast, struct token const *tokens);

/* debugger/lang/utils.c */
void debugger_lang_dump_lexer(struct lexer const *lexer);
void debugger_lang_dump_ast(struct ast const *ast);
void debugger_lang_cleanup(struct lexer *lexer, struct ast *ast, struct eval *eval);

/* debugger/lang/variables.c */
void debugger_lang_mut_variables_push(struct app *app, char const *name, uint32_t *);
void debugger_lang_const_variables_push(struct app *app, char const *name, uint32_t);
struct variable *debugger_lang_variables_lookup(struct app *app, char const *name);

#endif /* WITH_DEBUGGER */

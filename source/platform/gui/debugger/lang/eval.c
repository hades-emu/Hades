/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2022 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include "hades.h"
#include "platform/gui/app.h"
#include "platform/gui/debugger.h"
#include "platform/gui/lang.h"

int64_t
debugger_lang_eval_node(
    struct eval *eval,
    struct app *app,
    struct node const *node
) {
    switch (node->kind) {
        case NODE_LITTERAL: {
            return (node->value.litteral);
        };
        case NODE_VARIABLE: {
            struct variable *variable;

            variable = debugger_lang_variables_lookup(app, node->value.identifier);
            if (!variable) {
                free(eval->error);
                asprintf(&eval->error, "Undefined variable \"%s\"", node->value.identifier);
                return (0);
            }

            if (variable->mutable) {
                return (*variable->ptr);
            } else {
                return (variable->val);
            }
        };
        case NODE_OP_UNARY: {
            switch (node->value.operator) {
                case OP_UNARY_MINUS: return (-(debugger_lang_eval_node(eval, app, node->rhs)));
                case OP_UNARY_PLUS: return (+(debugger_lang_eval_node(eval, app, node->rhs)));
                default: panic(HS_DEBUG, "Unknown unary operator %i.", node->value.operator);
            }
            break;
        };
        case NODE_OP_BINARY: {
            switch (node->value.operator) {
                case _OP_BINARY_ASSIGN_START_ ... _OP_BINARY_ASSIGN_END_: {
                    struct variable *variable;

                    if (node->lhs->kind != NODE_VARIABLE) {
                        free(eval->error);
                        eval->error = strdup("Assigning a value to something that isn't a variable");
                        return (0);
                    }

                    variable = debugger_lang_variables_lookup(app, node->lhs->value.identifier);
                    if (!variable) {
                        free(eval->error);
                        asprintf(&eval->error, "Undefined variable \"%s\"", node->value.identifier);
                        return (0);
                    }

                    if (!variable->mutable) {
                        free(eval->error);
                        asprintf(&eval->error, "Variable \"%s\" is not mutable.", node->value.identifier);
                        return (0);
                    }

                    switch (node->value.operator) {
                        case OP_BINARY_ASSIGN: return (*variable->ptr = debugger_lang_eval_node(eval, app, node->rhs));
                        case OP_BINARY_ADDASSIGN: return (*variable->ptr += debugger_lang_eval_node(eval, app, node->rhs));
                        case OP_BINARY_SUBASSIGN: return (*variable->ptr -= debugger_lang_eval_node(eval, app, node->rhs));
                        case OP_BINARY_MULASSIGN: return (*variable->ptr *= debugger_lang_eval_node(eval, app, node->rhs));
                        case OP_BINARY_DIVASSIGN: return (*variable->ptr /= debugger_lang_eval_node(eval, app, node->rhs));
                        default: panic(HS_DEBUG, "Unknown binary operator %i.", node->value.operator);
                    }
                };
                case OP_BINARY_ADD: return (debugger_lang_eval_node(eval, app, node->lhs) + debugger_lang_eval_node(eval, app, node->rhs));
                case OP_BINARY_SUB: return (debugger_lang_eval_node(eval, app, node->lhs) - debugger_lang_eval_node(eval, app, node->rhs));
                case OP_BINARY_MUL: return (debugger_lang_eval_node(eval, app, node->lhs) * debugger_lang_eval_node(eval, app, node->rhs));
                case OP_BINARY_DIV: return (debugger_lang_eval_node(eval, app, node->lhs) / debugger_lang_eval_node(eval, app, node->rhs));
                default: panic(HS_DEBUG, "Unknown binary operator %i.", node->value.operator);
            }
        };
        default: panic(HS_DEBUG, "Unknown kind of node %i.", node->kind);
    }
}

void
debugger_lang_eval(
    struct eval *eval,
    struct app *app,
    struct ast const *ast
) {
    eval->res = debugger_lang_eval_node(eval, app, ast->root);
}
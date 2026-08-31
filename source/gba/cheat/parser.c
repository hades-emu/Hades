/******************************************************************************\
**
**  This file is part of the Hades GBA Emulator, and is made available under
**  the terms of the GNU General Public License version 2.
**
**  Copyright (C) 2021-2026 - The Hades Authors
**
\******************************************************************************/

#include <string.h>
#include <ctype.h>
#include "gba/gba.h"
#include "gba/cheat.h"

static
struct cheat_token *
cheat_token_new(
    struct cheat_compiler *compiler,
    int kind
) {
    struct cheat_token *t;

    t = malloc(sizeof(*t));
    hs_assert(t);

    memset(t, 0, sizeof(*t));
    t->kind = kind;
    t->next = NULL;

    if (compiler->last) {
        compiler->last->next = t;
    }

    compiler->last = t;

    if (!compiler->tokens) {
        compiler->tokens = t;
    }

    return (t);
}

static
void
cheat_compiler_cleanup(
    struct cheat_compiler *compiler
) {
    struct cheat_token *t;

    t = compiler->tokens;
    while (t) {
        struct cheat_token *next;

        next = t->next;
        free(t);
        t = next;
    }

    compiler->tokens = NULL;
    compiler->last = NULL;

    free(compiler->error);
    compiler->error = NULL;
}

static
uint32_t
cheat_lexe_hex_number(
    char const *str,
    size_t len
) {
    uint32_t out;
    size_t i;

    out = 0;
    for (i = 0; str[i] && i < len; ++i) {
        switch (str[i]) {
            case '0'...'9': {
                out *= 16;
                out += str[i] - '0';
                break;
            }
            case 'a'...'f': {
                out *= 16;
                out += 10 + (str[i] - 'a');
                break;
            }
            case 'A'...'F': {
                out *= 16;
                out += 10 + (str[i] - 'A');
                break;
            }
            default: {
                break;
            }
        }
    }

    return out;
}

static
void
cheat_lexe(
    struct cheat_compiler *compiler,
    char const *input
) {
    size_t i;

    i = 0;
    while (input[i]) {
        switch (input[i]) {
            case '0' ... '9':
            case 'a' ... 'f':
            case 'A' ... 'F': {
                /* Lexe the whole number */
                struct cheat_token *t;
                size_t j;

                j = 0;
                while (isxdigit(input[i + j]) && j < 8) {
                    ++j;
                }

                switch (j) {
                    case 8: {
                        t = cheat_token_new(compiler, CHEAT_TOKEN_KIND_U32);
                        t->value.u32 = cheat_lexe_hex_number(input + i, 8);
                        break;
                    }
                    case 4: {
                        t = cheat_token_new(compiler, CHEAT_TOKEN_KIND_U16);
                        t->value.u16 = cheat_lexe_hex_number(input + i, 4);
                        break;
                    }
                    case 2: {
                        t = cheat_token_new(compiler, CHEAT_TOKEN_KIND_U8);
                        t->value.u8 = cheat_lexe_hex_number(input + i, 2);
                        break;
                    }
                    default: {
                        compiler->error = hs_format("Invalid hex number of %zu digits", j);
                        return;
                    }
                }

                i += j;
                break;
            };
            case '#': {
                while (input[i] && input[i] != '\n') {
                    ++i;
                }
                break;
            }
            case ' ':
            case '\r':
            case '\n':
            case '\t': {
                ++i;
                break;
            };
            default: {
                compiler->error = hs_format("Invalid character \'%c\'", input[i]);
                return;
            };
        }
    }
}

static
void
cheat_compilation_error_own(
    struct gba_cheat_raw *raw,
    char *error
) {
    raw->compilation.finished = true;
    raw->compilation.success = false;
    raw->compilation.error = error;
}

static
void
cheat_compilation_error_copy(
    struct gba_cheat_raw *raw,
    char *error
) {
    raw->compilation.finished = true;
    raw->compilation.success = false;
    raw->compilation.error = strdup(error);
}

bool
cheat_parse_and_compile(
    struct cheat_bin *bin,
    struct gba_cheat_raw *raw
) {
    struct cheat_compiler compiler;
    bool ret;

    // Reset the compilation's state to success
    raw->compilation.finished = true;
    raw->compilation.success = true;
    free(raw->compilation.error);
    raw->compilation.error = NULL;

    memset(&compiler, 0, sizeof(struct cheat_compiler));
    memset(bin, 0, sizeof(struct cheat_bin));

    cheat_lexe(&compiler, raw->code);

    if (compiler.error) {
        cheat_compilation_error_copy(raw, compiler.error);
        logln(HS_ERROR, "Failed to parse cheat: %s.", compiler.error);
        ret = false;
        goto end;
    }

    switch (raw->kind) {
        case RAW_CHEAT_KIND_PARV3: {
            if (!cheat_parv3_compile(bin, &compiler)) {
                cheat_compilation_error_own(raw, hs_format("PARV3: %s", compiler.error));
                logln(HS_ERROR, "Failed to compile PARV3 cheat: %s.", compiler.error);
                ret = false;
                goto end;
            }

            ret = true;
            goto end;
        }
        default: {
            cheat_compilation_error_own(raw, hs_format("Unsupported cheat type %i", raw->kind));
            logln(HS_WARN, "Unsupported cheat type %i.", raw->kind);
            ret = false;
            goto end;
        }
    }

    panic(HS_ERROR, "Reached supposedly unreachable code in `cheat_parse_and_compile()`.");

end:
    cheat_compiler_cleanup(&compiler);
    return ret;
}

bool
cheat_parse(
    struct gba_cheat_raw *raw
) {
    struct cheat_bin bin;
    bool ret;

    ret = cheat_parse_and_compile(&bin, raw);
    cheat_delete(&bin);

    return ret;
}

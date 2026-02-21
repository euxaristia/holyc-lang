#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

#include "aostr.h"
#include "ir-debug.h"
#include "ir-types.h"
#include "util.h"

#define IR_VALUE_FLAG_ADDRESS (1ULL << 0)
#define IR_VALUE_FLAG_DEREF   (1ULL << 1)

typedef struct AArch64Ctx {
    u32 stack_size;
    u16 current_label_id;
    u16 return_label_id;
    u32 sp_bias;
    AoStr *buf;
    IrProgram *ir_program;
    Map *var_offsets;
    Set *registers;
    Set *alloca_tmps;
    Set *string_labels;
    List *string_values;
    u64 int_reg_cnt;
} AArch64Ctx;

AArch64Ctx *aarch64CtxNew(IrProgram *ir_program) {
    AArch64Ctx *ctx = malloc(sizeof(AArch64Ctx));
    memset(ctx, 0, sizeof(AArch64Ctx));
    ctx->ir_program = ir_program;
    ctx->buf = aoStrNew();
    ctx->var_offsets = mapNew(8, &map_uint_to_uint_type);
    ctx->registers = setNew(32, &set_uint_type);
    ctx->alloca_tmps = setNew(64, &set_uint_type);
    ctx->string_labels = setNew(32, &set_cstring_type);
    ctx->string_values = listNew();
    ctx->int_reg_cnt = 0;
    return ctx;
}

/* Does not release the assembly String buffer */
void aarch64CtxRelease(AArch64Ctx *ctx) {
    if (ctx) {
        mapRelease(ctx->var_offsets);
        setRelease(ctx->registers);
        setRelease(ctx->alloca_tmps);
        setRelease(ctx->string_labels);
        listRelease(ctx->string_values, NULL);
        free(ctx);
    }
}

u32 aarch64GetIntRegister(AArch64Ctx *ctx) {
    return ctx->int_reg_cnt++;
}

void aarch64ClearIntRegisters(AArch64Ctx *ctx) {
    ctx->int_reg_cnt = 0;
}

u32 aarch64CtxGetVarOffset(AArch64Ctx *ctx, u32 var_id) {
    return (u32)(u64)(void *)mapGetInt(ctx->var_offsets, var_id);
}

void aarch64CtxSetVarOffset(AArch64Ctx *ctx, u32 var_id, u32 offset) {
    mapAddIntOrErr(ctx->var_offsets, var_id, (void *)(u64)offset);
}

u32 aarch64GetFreeReg(AArch64Ctx *ctx) {
    (void)ctx;
    return 0;
} 

int alignTo(int value, int alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

const char *aarch64CmpCond(IrCmpKind cmp_kind) {
    switch (cmp_kind) {
        case IR_CMP_EQ:
            return "eq";
        case IR_CMP_NE:
            return "ne";
        case IR_CMP_LT:
            return "lt";
        case IR_CMP_LE:
            return "le";
        case IR_CMP_GT:
            return "gt";
        case IR_CMP_GE:
            return "ge";
        case IR_CMP_ULT:
            return "lo";
        case IR_CMP_ULE:
            return "ls";
        case IR_CMP_UGT:
            return "hi";
        case IR_CMP_UGE:
            return "hs";
        case IR_CMP_OEQ:
            return "eq";
        case IR_CMP_ONE:
            return "ne";
        case IR_CMP_OLT:
            return "lt";
        case IR_CMP_OLE:
            return "le";
        case IR_CMP_OGT:
            return "gt";
        case IR_CMP_OGE:
            return "ge";
        case IR_CMP_UNO:
            return "vs";
        case IR_CMP_ORD:
            return "vc";
        case IR_CMP_INVALID:
        default:
            loggerPanic("Unhandled cmp kind: %d\n", cmp_kind);
    }
}

int aarch64IsFloatType(IrValueType type) {
    return type == IR_TYPE_F64;
}

static AoStr *aarch64NormaliseFunctionName(AoStr *name) {
    AoStr *normalised = aoStrDup(name);
    if (normalised && normalised->len >= 4 &&
        strncasecmp(normalised->data, "Main", 4) == 0) {
        aoStrToLowerCase(normalised);
    }
    return normalised;
}

void aarch64CollectConstStringValue(AArch64Ctx *ctx, IrValue *value) {
    if (!value) return;

    if (value->kind == IR_VAL_CONST_STR) {
        if (!value->as.str.label || !value->as.str.str) return;
        if (!setHasLen(ctx->string_labels,
                       value->as.str.label->data,
                       value->as.str.label->len)) {
            setAdd(ctx->string_labels, value->as.str.label->data);
            listAppend(ctx->string_values, value);
        }
        return;
    }

    if (value->type == IR_TYPE_ARRAY && value->as.array.values) {
        for (u64 i = 0; i < value->as.array.values->size; ++i) {
            IrValue *entry = value->as.array.values->entries[i];
            aarch64CollectConstStringValue(ctx, entry);
        }
    }
}

void aarch64CollectConstStrings(AArch64Ctx *ctx, IrProgram *program) {
    for (u64 i = 0; i < program->functions->size; ++i) {
        IrFunction *func = program->functions->entries[i];
        listForEach(func->blocks) {
            IrBlock *block = listValue(IrBlock *, it);
            listForEach(block->instructions) {
                IrInstr *instr = listValue(IrInstr *, it);
                aarch64CollectConstStringValue(ctx, instr->dst);
                aarch64CollectConstStringValue(ctx, instr->r1);
                aarch64CollectConstStringValue(ctx, instr->r2);
            }
        }
    }
}

void aarch64EmitConstStrings(AArch64Ctx *ctx) {
    if (listEmpty(ctx->string_values)) {
        aoStrCatFmt(ctx->buf, ".text\n\t");
        return;
    }

    aoStrCatFmt(ctx->buf, ".section .rodata\n");
    listForEach(ctx->string_values) {
        IrValue *value = listValue(IrValue *, it);
        aoStrCatFmt(ctx->buf,
                    "%S:\n\t"
                    ".asciz \"%S\"\n",
                    value->as.str.label,
                    value->as.str.str);
    }
    aoStrCatFmt(ctx->buf, ".text\n\t");
}

void aarch64MovImm64(AArch64Ctx *ctx, u32 reg, u64 imm) {
    int emitted = 0;
    for (u32 shift = 0; shift < 64; shift += 16) {
        u32 chunk = (u32)((imm >> shift) & 0xffffULL);
        if (chunk == 0 && emitted) continue;
        if (!emitted) {
            aoStrCatFmt(ctx->buf, "movz x%u, #%u, lsl #%u\n\t", reg, chunk, shift);
            emitted = 1;
        } else {
            aoStrCatFmt(ctx->buf, "movk x%u, #%u, lsl #%u\n\t", reg, chunk, shift);
        }
    }
    if (!emitted) {
        aoStrCatFmt(ctx->buf, "mov x%u, #0\n\t", reg);
    }
}

static void aarch64AddStackOffset(AArch64Ctx *ctx, u32 addr_reg, u32 scratch_reg, u32 offset) {
    if (offset <= 4095) {
        aoStrCatFmt(ctx->buf, "add x%u, sp, #%u\n\t", addr_reg, offset);
        return;
    }
    aarch64MovImm64(ctx, scratch_reg, offset);
    aoStrCatFmt(ctx->buf, "add x%u, sp, x%u\n\t", addr_reg, scratch_reg);
}

static void aarch64AddLocalStackOffset(AArch64Ctx *ctx, u32 addr_reg, u32 scratch_reg, u32 offset) {
    aarch64AddStackOffset(ctx, addr_reg, scratch_reg, offset + ctx->sp_bias);
}

static void aarch64LoadPtrValue(AArch64Ctx *ctx, IrValue *value, u32 reg);

static void aarch64LoadStackSlotAddress(AArch64Ctx *ctx, IrValue *value, u32 reg) {
    if (!value) return;
    if (value->kind != IR_VAL_LOCAL &&
        value->kind != IR_VAL_PARAM &&
        value->kind != IR_VAL_TMP) {
        loggerPanic("AArch64 backend: slot address requested for non-stack value `%s`\n",
                irValueKindToString(value->kind));
    }
    u32 offset = aarch64CtxGetVarOffset(ctx, value->as.var.id);
    assert(offset != 0 || ctx->stack_size == 0);
    aarch64AddLocalStackOffset(ctx, 14, 15, offset);
    aoStrCatFmt(ctx->buf, "mov x%u, x14\n\t", reg);
}

static void aarch64ComputeLValueAddress(AArch64Ctx *ctx, IrValue *value, u32 reg) {
    if (!value) return;

    if (value->flags & IR_VALUE_FLAG_DEREF) {
        aarch64LoadPtrValue(ctx, value, reg);
        return;
    }

    switch (value->kind) {
        case IR_VAL_GLOBAL:
            if (!value->as.global.name) {
                loggerPanic("AArch64 backend: global lvalue missing symbol\n");
            }
            aoStrCatFmt(ctx->buf, "adrp x%u, %S\n\t", reg, value->as.global.name);
            aoStrCatFmt(ctx->buf, "add x%u, x%u, :lo12:%S\n\t",
                        reg, reg, value->as.global.name);
            return;
        case IR_VAL_LOCAL:
        case IR_VAL_PARAM:
            aarch64LoadStackSlotAddress(ctx, value, reg);
            return;
        case IR_VAL_TMP:
            if (setHas(ctx->alloca_tmps, (void *)(u64)value->as.var.id)) {
                aarch64LoadStackSlotAddress(ctx, value, reg);
            } else {
                aarch64LoadPtrValue(ctx, value, reg);
            }
            return;
        default:
            loggerPanic("AArch64 backend: cannot form lvalue address from `%s`\n",
                    irValueKindToString(value->kind));
    }
}

static void aarch64AdjustSp(AArch64Ctx *ctx, int is_add, u32 amount) {
    if (!amount) return;
    if (amount <= 4095) {
        aoStrCatFmt(ctx->buf, "%s sp, sp, #%u\n\t", is_add ? "add" : "sub", amount);
        return;
    }
    aarch64MovImm64(ctx, 9, amount);
    aoStrCatFmt(ctx->buf, "%s sp, sp, x9\n\t", is_add ? "add" : "sub");
}

static void aarch64EmitGlobals(AArch64Ctx *ctx) {
    if (!ctx->ir_program || !ctx->ir_program->globals) return;
    for (u64 i = 0; i < ctx->ir_program->globals->size; ++i) {
        IrValue *global = ctx->ir_program->globals->entries[i];
        if (!global || global->kind != IR_VAL_GLOBAL || !global->as.global.name) continue;
        u64 size = global->flags ? global->flags : 8;
        if (global->as.global.name->data[0] != '.') {
            aoStrCatFmt(ctx->buf, ".globl %S\n", global->as.global.name);
        }

        if (!global->as.global.value) {
            aoStrCatFmt(ctx->buf, ".bss\n"
                                  ".align 3\n"
                                  "%S:\n"
                                  "\t.skip %u\n",
                    global->as.global.name, (u32)size);
            continue;
        }

        aoStrCatFmt(ctx->buf, ".data\n"
                              ".align 3\n"
                              "%S:\n",
                global->as.global.name);
        if (global->as.global.value->kind == IR_VAL_CONST_INT) {
            aoStrCatFmt(ctx->buf, "\t.quad %lld\n", global->as.global.value->as._i64);
        } else if (global->as.global.value->kind == IR_VAL_CONST_STR &&
                   global->as.global.value->as.str.label) {
            aoStrCatFmt(ctx->buf, "\t.quad %S\n", global->as.global.value->as.str.label);
        } else {
            aoStrCatFmt(ctx->buf, "\t.skip %u\n", (u32)size);
        }
    }
}

void aarch64LoadIntValue(AArch64Ctx *ctx, IrValue *value, u32 reg) {
    switch (value->kind) {
        case IR_VAL_CONST_INT:
            aarch64MovImm64(ctx, reg, (u64)value->as._i64);
            return;
        case IR_VAL_CONST_FLOAT: {
            union {
                f64 f;
                u64 u;
            } as_u64;
            as_u64.f = value->as._f64;
            aarch64MovImm64(ctx, reg, as_u64.u);
            return;
        }
        case IR_VAL_LOCAL:
        case IR_VAL_PARAM:
        case IR_VAL_TMP: {
            u32 offset = aarch64CtxGetVarOffset(ctx, value->as.var.id);
            assert(offset != 0 || ctx->stack_size == 0);
            aarch64AddLocalStackOffset(ctx, 14, 15, offset);
            if ((value->flags & IR_VALUE_FLAG_ADDRESS) &&
                ((value->kind == IR_VAL_LOCAL || value->kind == IR_VAL_PARAM) ||
                 (value->kind == IR_VAL_TMP &&
                  setHas(ctx->alloca_tmps, (void *)(u64)value->as.var.id)))) {
                aoStrCatFmt(ctx->buf, "mov x%u, x14\n\t", reg);
                return;
            }
            switch (value->type) {
                case IR_TYPE_I8:
                    aoStrCatFmt(ctx->buf, "ldrb w%u, [x14]\n\t", reg);
                    return;
                case IR_TYPE_I16:
                    aoStrCatFmt(ctx->buf, "ldrh w%u, [x14]\n\t", reg);
                    return;
                case IR_TYPE_I32:
                    aoStrCatFmt(ctx->buf, "ldrsw x%u, [x14]\n\t", reg);
                    return;
                case IR_TYPE_I64:
                case IR_TYPE_PTR:
                case IR_TYPE_FUNCTION:
                case IR_TYPE_ASM_FUNCTION:
                case IR_TYPE_LABEL:
                    aoStrCatFmt(ctx->buf, "ldr x%u, [x14]\n\t", reg);
                    return;
                case IR_TYPE_ARRAY:
                case IR_TYPE_ARRAY_INIT:
                case IR_TYPE_STRUCT:
                    /* Aggregate values live in stack slots; scalar loads of
                     * array/struct typed values must materialize the address. */
                    aoStrCatFmt(ctx->buf, "mov x%u, x14\n\t", reg);
                    return;
                case IR_TYPE_VOID:
                    /* Defensive fallback: void-typed temporaries can leak
                     * into lowered IR; materialize a neutral value. */
                    aoStrCatFmt(ctx->buf, "mov x%u, #0\n\t", reg);
                    return;
                case IR_TYPE_F64:
                    aoStrCatFmt(ctx->buf, "ldr d15, [x14]\n\t");
                    aoStrCatFmt(ctx->buf, "fmov x%u, d15\n\t", reg);
                    return;
                default:
                    loggerPanic("Unhandled int load type: %s\n",
                            irValueTypeToString(value->type));
            }
        }
        case IR_VAL_GLOBAL:
            if (value->as.global.name) {
                aoStrCatFmt(ctx->buf, "adrp x%u, %S\n\t", reg, value->as.global.name);
                aoStrCatFmt(ctx->buf, "add x%u, x%u, :lo12:%S\n\t",
                            reg, reg, value->as.global.name);
                return;
            }
            loggerPanic("AArch64 backend: global value missing symbol\n");
            break;
        case IR_VAL_CONST_STR:
            aoStrCatFmt(ctx->buf, "adrp x%u, %S\n\t", reg, value->as.str.label);
            aoStrCatFmt(ctx->buf, "add x%u, x%u, :lo12:%S\n\t",
                        reg, reg, value->as.str.label);
            return;
        case IR_VAL_PHI:
        case IR_VAL_LABEL:
        case IR_VAL_UNDEFINED:
        case IR_VAL_UNRESOLVED:
            loggerPanic("AArch64 backend: unsupported int value kind `%s`\n",
                    irValueKindToString(value->kind));
            break;
    }
}

/* Address-flagged pointer temps are l-values in IR.
 * For memory ops we need the pointer value stored in the slot, not the slot address. */
static void aarch64LoadPtrValue(AArch64Ctx *ctx, IrValue *value, u32 reg) {
    if (!value) return;
    IrValue tmp = *value;
    tmp.flags &= ~IR_VALUE_FLAG_ADDRESS;
    aarch64LoadIntValue(ctx, &tmp, reg);
}

void aarch64StoreIntValue(AArch64Ctx *ctx, IrValue *dest, u32 reg) {
    if (!dest || dest->type == IR_TYPE_VOID) return;
    if (dest->kind != IR_VAL_LOCAL &&
        dest->kind != IR_VAL_PARAM &&
        dest->kind != IR_VAL_TMP) {
        return;
    }
    u32 offset = aarch64CtxGetVarOffset(ctx, dest->as.var.id);
    assert(offset != 0 || ctx->stack_size == 0);
    aarch64AddLocalStackOffset(ctx, 14, 15, offset);
    switch (dest->type) {
        case IR_TYPE_I8:
            aoStrCatFmt(ctx->buf, "strb w%u, [x14]\n\t", reg);
            return;
        case IR_TYPE_I16:
            aoStrCatFmt(ctx->buf, "strh w%u, [x14]\n\t", reg);
            return;
        case IR_TYPE_I32:
            aoStrCatFmt(ctx->buf, "str w%u, [x14]\n\t", reg);
            return;
        case IR_TYPE_I64:
        case IR_TYPE_PTR:
        case IR_TYPE_ARRAY:
        case IR_TYPE_ARRAY_INIT:
        case IR_TYPE_STRUCT:
        case IR_TYPE_FUNCTION:
        case IR_TYPE_ASM_FUNCTION:
        case IR_TYPE_LABEL:
            aoStrCatFmt(ctx->buf, "str x%u, [x14]\n\t", reg);
            return;
        case IR_TYPE_F64:
            aoStrCatFmt(ctx->buf, "fmov d15, x%u\n\t", reg);
            aoStrCatFmt(ctx->buf, "str d15, [x14]\n\t");
            return;
        default:
            loggerPanic("Unhandled int store type: %s\n",
                    irValueTypeToString(dest->type));
    }
}

void aarch64LoadFloatValue(AArch64Ctx *ctx, IrValue *value, u32 reg) {
    switch (value->kind) {
        case IR_VAL_CONST_INT:
            aarch64MovImm64(ctx, reg, (u64)value->as._i64);
            aoStrCatFmt(ctx->buf, "scvtf d%u, x%u\n\t", reg, reg);
            return;
        case IR_VAL_LOCAL:
        case IR_VAL_PARAM:
        case IR_VAL_TMP: {
            u32 offset = aarch64CtxGetVarOffset(ctx, value->as.var.id);
            assert(offset != 0 || ctx->stack_size == 0);
            aarch64AddLocalStackOffset(ctx, 14, 15, offset);
            aoStrCatFmt(ctx->buf, "ldr d%u, [x14]\n\t", reg);
            return;
        }
        case IR_VAL_CONST_FLOAT: {
            union {
                f64 f;
                u64 u;
            } as_u64;
            as_u64.f = value->as._f64;
            aarch64MovImm64(ctx, reg, as_u64.u);
            aoStrCatFmt(ctx->buf, "fmov d%u, x%u\n\t", reg, reg);
            return;
        }
        case IR_VAL_GLOBAL:
        case IR_VAL_CONST_STR:
        case IR_VAL_PHI:
        case IR_VAL_LABEL:
        case IR_VAL_UNDEFINED:
        case IR_VAL_UNRESOLVED:
            loggerPanic("AArch64 backend: unsupported float value kind `%s`\n",
                    irValueKindToString(value->kind));
            break;
    }
}

void aarch64StoreFloatValue(AArch64Ctx *ctx, IrValue *dest, u32 reg) {
    if (!dest || dest->type == IR_TYPE_VOID) return;
    if (dest->kind != IR_VAL_LOCAL &&
        dest->kind != IR_VAL_PARAM &&
        dest->kind != IR_VAL_TMP) {
        return;
    }
    u32 offset = aarch64CtxGetVarOffset(ctx, dest->as.var.id);
    assert(offset != 0 || ctx->stack_size == 0);
    aarch64AddLocalStackOffset(ctx, 14, 15, offset);
    aoStrCatFmt(ctx->buf, "str d%u, [x14]\n\t", reg);
}

void aarch64GenStore(AArch64Ctx *ctx, IrValue *dest, char *reg) {
    assert(dest);
    switch (dest->kind) {
        case IR_VAL_GLOBAL:
            break;

        case IR_VAL_TMP:
        case IR_VAL_LOCAL:
        case IR_VAL_PARAM: {
            u32 regn = (u32)strtoul(reg + 1, NULL, 10);
            if (aarch64IsFloatType(dest->type)) {
                aarch64StoreFloatValue(ctx, dest, regn);
            } else {
                aarch64StoreIntValue(ctx, dest, regn);
            }
            break;
        }
        default:
            loggerPanic("Unsupported store: %s\n", irValueKindToString(dest->kind));
    }
}

IrPair *aarch64FindPhiIncoming(IrInstr *phi, IrBlock *from_block) {
    if (!phi || phi->op != IR_PHI || !phi->extra.phi_pairs) return NULL;
    for (u64 i = 0; i < phi->extra.phi_pairs->size; ++i) {
        IrPair *pair = vecGet(IrPair *, phi->extra.phi_pairs, i);
        if (pair->ir_block == from_block) {
            return pair;
        }
    }
    return NULL;
}

u32 aarch64CountPhiCopiesForEdge(IrBlock *target_block, IrBlock *from_block) {
    u32 count = 0;
    listForEach(target_block->instructions) {
        IrInstr *instr = listValue(IrInstr *, it);
        if (instr->op != IR_PHI) continue;
        if (aarch64FindPhiIncoming(instr, from_block)) {
            count++;
        }
    }
    return count;
}

void aarch64EmitPhiCopiesForEdge(AArch64Ctx *ctx,
                                 IrBlock *target_block,
                                 IrBlock *from_block)
{
    listForEach(target_block->instructions) {
        IrInstr *phi = listValue(IrInstr *, it);
        if (phi->op != IR_PHI) continue;
        IrPair *incoming = aarch64FindPhiIncoming(phi, from_block);
        if (!incoming || !phi->dst) continue;

        if (aarch64IsFloatType(phi->dst->type)) {
            aarch64LoadFloatValue(ctx, incoming->ir_value, 15);
            aarch64StoreFloatValue(ctx, phi->dst, 15);
        } else {
            aarch64LoadIntValue(ctx, incoming->ir_value, 15);
            aarch64StoreIntValue(ctx, phi->dst, 15);
        }
    }
}

void aarch64GenInstr(AArch64Ctx *ctx, IrInstr *instr, IrInstr *next_instr, IrBlock *cur_block) {
    (void)next_instr;
    switch (instr->op) {
        case IR_NOP:
        case IR_ALLOCA:
            break;

        case IR_STORE: {
            if (instr->dst->kind == IR_VAL_GLOBAL && instr->dst->as.global.name) {
                aoStrCatFmt(ctx->buf, "adrp x9, %S\n\t", instr->dst->as.global.name);
                aoStrCatFmt(ctx->buf, "add x9, x9, :lo12:%S\n\t", instr->dst->as.global.name);
                if (aarch64IsFloatType(instr->r1->type)) {
                    aarch64LoadFloatValue(ctx, instr->r1, 8);
                    aoStrCatFmt(ctx->buf, "str d8, [x9]\n\t");
                } else {
                    aarch64LoadIntValue(ctx, instr->r1, 8);
                    switch (instr->r1->type) {
                        case IR_TYPE_I8:
                            aoStrCatFmt(ctx->buf, "strb w8, [x9]\n\t");
                            break;
                        case IR_TYPE_I16:
                            aoStrCatFmt(ctx->buf, "strh w8, [x9]\n\t");
                            break;
                        case IR_TYPE_I32:
                            aoStrCatFmt(ctx->buf, "str w8, [x9]\n\t");
                            break;
                        default:
                            aoStrCatFmt(ctx->buf, "str x8, [x9]\n\t");
                            break;
                    }
                }
                break;
            }
            if (instr->dst->flags & IR_VALUE_FLAG_ADDRESS) {
                aarch64ComputeLValueAddress(ctx, instr->dst, 9);
                if (aarch64IsFloatType(instr->r1->type)) {
                    aarch64LoadFloatValue(ctx, instr->r1, 8);
                    aoStrCatFmt(ctx->buf, "str d8, [x9]\n\t");
                } else {
                    aarch64LoadIntValue(ctx, instr->r1, 8);
                    switch (instr->r1->type) {
                        case IR_TYPE_I8:
                            aoStrCatFmt(ctx->buf, "strb w8, [x9]\n\t");
                            break;
                        case IR_TYPE_I16:
                            aoStrCatFmt(ctx->buf, "strh w8, [x9]\n\t");
                            break;
                        case IR_TYPE_I32:
                            aoStrCatFmt(ctx->buf, "str w8, [x9]\n\t");
                            break;
                        default:
                            aoStrCatFmt(ctx->buf, "str x8, [x9]\n\t");
                            break;
                    }
                }
                break;
            }
            if (aarch64IsFloatType(instr->dst->type)) {
                aarch64LoadFloatValue(ctx, instr->r1, 0);
                aarch64StoreFloatValue(ctx, instr->dst, 0);
            } else {
                aarch64LoadIntValue(ctx, instr->r1, 8);
                aarch64StoreIntValue(ctx, instr->dst, 8);
            }
            break;
        }

        case IR_LOAD: {
            if ((instr->r1->flags & IR_VALUE_FLAG_ADDRESS) ||
                instr->r1->kind == IR_VAL_GLOBAL) {
                aarch64ComputeLValueAddress(ctx, instr->r1, 9);
                if (aarch64IsFloatType(instr->dst->type)) {
                    aoStrCatFmt(ctx->buf, "ldr d8, [x9]\n\t");
                    aarch64StoreFloatValue(ctx, instr->dst, 8);
                } else {
                    switch (instr->dst->type) {
                        case IR_TYPE_I8:
                            aoStrCatFmt(ctx->buf, "ldrb w8, [x9]\n\t");
                            break;
                        case IR_TYPE_I16:
                            aoStrCatFmt(ctx->buf, "ldrh w8, [x9]\n\t");
                            break;
                        case IR_TYPE_I32:
                            aoStrCatFmt(ctx->buf, "ldr w8, [x9]\n\t");
                            break;
                        default:
                            aoStrCatFmt(ctx->buf, "ldr x8, [x9]\n\t");
                            break;
                    }
                    aarch64StoreIntValue(ctx, instr->dst, 8);
                }
                break;
            }
            if (aarch64IsFloatType(instr->dst->type)) {
                aarch64LoadFloatValue(ctx, instr->r1, 8);
                aarch64StoreFloatValue(ctx, instr->dst, 8);
            } else {
                aarch64LoadIntValue(ctx, instr->r1, 8);
                aarch64StoreIntValue(ctx, instr->dst, 8);
            }
            break;
        }

        case IR_IADD: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "add x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_CALL: {
            IrValueArray *args = &instr->r1->as.array;
            u32 gp_reg = 0;
            u32 fp_reg = 0;
            u32 stack_bytes = 0;
            for (u64 i = 0; i < args->values->size; ++i) {
                IrValue *arm = args->values->entries[i];
                if (aarch64IsFloatType(arm->type)) {
                    if (fp_reg < 8) {
                        fp_reg++;
                    } else {
                        stack_bytes += 8;
                    }
                } else {
                    if (gp_reg < 8) {
                        gp_reg++;
                    } else {
                        stack_bytes += 8;
                    }
                }
            }
            u32 call_stack_size = (u32)alignTo((int)stack_bytes, 16);
            if (call_stack_size) {
                aarch64AdjustSp(ctx, 0, call_stack_size);
                ctx->sp_bias = call_stack_size;
            }

            gp_reg = 0;
            fp_reg = 0;
            u32 stack_offset = 0;
            for (u64 i = 0; i < args->values->size; ++i) {
                IrValue *arm = args->values->entries[i];
                if (aarch64IsFloatType(arm->type)) {
                    if (fp_reg < 8) {
                        aarch64LoadFloatValue(ctx, arm, fp_reg);
                        fp_reg++;
                    } else {
                        aarch64LoadFloatValue(ctx, arm, 15);
                        aarch64AddStackOffset(ctx, 14, 12, stack_offset);
                        aoStrCatFmt(ctx->buf, "str d15, [x14]\n\t");
                        stack_offset += 8;
                    }
                } else {
                    if (gp_reg < 8) {
                        aarch64LoadIntValue(ctx, arm, gp_reg);
                        gp_reg++;
                    } else {
                        aarch64LoadIntValue(ctx, arm, 9);
                        aarch64AddStackOffset(ctx, 14, 12, stack_offset);
                        aoStrCatFmt(ctx->buf, "str x9, [x14]\n\t");
                        stack_offset += 8;
                    }
                }
            }

            if (instr->r2) {
                aarch64LoadIntValue(ctx, instr->r2, 16);
                aoStrCatFmt(ctx->buf, "blr x16\n\t");
            } else {
                AoStr *target_name = aarch64NormaliseFunctionName(args->label);
                aoStrCatFmt(ctx->buf, "bl %S\n\t", target_name);
                aoStrRelease(target_name);
            }
            if (call_stack_size) {
                ctx->sp_bias = 0;
                aarch64AdjustSp(ctx, 1, call_stack_size);
            }
            if (instr->dst) {
                if (aarch64IsFloatType(instr->dst->type)) {
                    aarch64StoreFloatValue(ctx, instr->dst, 0);
                } else {
                    aarch64StoreIntValue(ctx, instr->dst, 0);
                }
            }
            break;
        }

        case IR_GEP:
        case IR_ISUB: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "sub x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_IMUL: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "mul x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_IDIV: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "sdiv x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_UDIV: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "udiv x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_IREM: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "sdiv x9, x0, x1\n\t");
            aoStrCatFmt(ctx->buf, "msub x8, x9, x1, x0\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_UREM: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "udiv x9, x0, x1\n\t");
            aoStrCatFmt(ctx->buf, "msub x8, x9, x1, x0\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_INEG: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "neg x8, x0\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_AND: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "and x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_OR: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "orr x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_XOR: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "eor x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_SHL: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "lsl x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_SHR: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "lsr x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_SAR: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "asr x8, x0, x1\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_NOT: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "mvn x8, x0\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_ICMP: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aarch64LoadIntValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "cmp x0, x1\n\t");
            aoStrCatFmt(ctx->buf, "cset w8, %s\n\t", aarch64CmpCond(instr->extra.cmp_kind));
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FADD: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aarch64LoadFloatValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "fadd d8, d0, d1\n\t");
            if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FSUB: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aarch64LoadFloatValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "fsub d8, d0, d1\n\t");
            if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FMUL: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aarch64LoadFloatValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "fmul d8, d0, d1\n\t");
            if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FDIV: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aarch64LoadFloatValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "fdiv d8, d0, d1\n\t");
            if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FNEG: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "fneg d8, d0\n\t");
            if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FCMP: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aarch64LoadFloatValue(ctx, instr->r2, 1);
            aoStrCatFmt(ctx->buf, "fcmp d0, d1\n\t");
            aoStrCatFmt(ctx->buf, "cset w8, %s\n\t", aarch64CmpCond(instr->extra.cmp_kind));
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_ZEXT: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            switch (instr->r1 ? instr->r1->type : IR_TYPE_VOID) {
                case IR_TYPE_I8:
                    aoStrCatFmt(ctx->buf, "uxtb x8, w0\n\t");
                    break;
                case IR_TYPE_I16:
                    aoStrCatFmt(ctx->buf, "uxth x8, w0\n\t");
                    break;
                case IR_TYPE_I32:
                    aoStrCatFmt(ctx->buf, "mov w8, w0\n\t");
                    break;
                default:
                    aoStrCatFmt(ctx->buf, "mov x8, x0\n\t");
                    break;
            }
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_SEXT: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            switch (instr->r1 ? instr->r1->type : IR_TYPE_VOID) {
                case IR_TYPE_I8:
                    aoStrCatFmt(ctx->buf, "sxtb x8, w0\n\t");
                    break;
                case IR_TYPE_I16:
                    aoStrCatFmt(ctx->buf, "sxth x8, w0\n\t");
                    break;
                case IR_TYPE_I32:
                    aoStrCatFmt(ctx->buf, "sxtw x8, w0\n\t");
                    break;
                default:
                    aoStrCatFmt(ctx->buf, "mov x8, x0\n\t");
                    break;
            }
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_TRUNC: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "mov w8, w0\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FPTRUNC:
        case IR_FPEXT: {
            if (instr->r1 && aarch64IsFloatType(instr->r1->type)) {
                aarch64LoadFloatValue(ctx, instr->r1, 0);
                aoStrCatFmt(ctx->buf, "fmov d8, d0\n\t");
                if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            } else {
                aarch64LoadIntValue(ctx, instr->r1, 0);
                aoStrCatFmt(ctx->buf, "mov x8, x0\n\t");
                if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            }
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FPTOUI: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "fcvtzu x8, d0\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_FPTOSI: {
            aarch64LoadFloatValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "fcvtzs x8, d0\n\t");
            if (instr->dst) aarch64StoreIntValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_UITOFP: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "ucvtf d8, x0\n\t");
            if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_SITOFP: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "scvtf d8, x0\n\t");
            if (instr->dst) aarch64StoreFloatValue(ctx, instr->dst, 8);
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_PTRTOINT:
        case IR_INTTOPTR:
        case IR_BITCAST: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "mov x8, x0\n\t");
            if (instr->dst) {
                if (aarch64IsFloatType(instr->dst->type)) {
                    aoStrCatFmt(ctx->buf, "fmov d8, x8\n\t");
                    aarch64StoreFloatValue(ctx, instr->dst, 8);
                } else {
                    aarch64StoreIntValue(ctx, instr->dst, 8);
                }
            }
            aarch64ClearIntRegisters(ctx);
            break;
        }

        case IR_RET: {
            if (instr->r1) {
                if (aarch64IsFloatType(instr->r1->type)) {
                    aarch64LoadFloatValue(ctx, instr->r1, 0);
                } else {
                    aarch64LoadIntValue(ctx, instr->r1, 0);
                }
            }
            aoStrCatFmt(ctx->buf, "b .Lret%u\n\t", ctx->return_label_id);
            break;
        }

        case IR_BR: {
            IrBlock *true_block = instr->extra.blocks.target_block;
            IrBlock *false_block = instr->extra.blocks.fallthrough_block;
            u32 true_phi_cnt = aarch64CountPhiCopiesForEdge(true_block, cur_block);
            u32 false_phi_cnt = aarch64CountPhiCopiesForEdge(false_block, cur_block);
            aarch64LoadIntValue(ctx, instr->dst, 0);
            if (true_phi_cnt == 0 && false_phi_cnt == 0) {
                aoStrCatFmt(ctx->buf, "cbnz x0, .LB%u\n\t", true_block->id);
                aoStrCatFmt(ctx->buf, "b .LB%u\n\t", false_block->id);
                break;
            }

            u32 true_copy_label = ctx->current_label_id++;
            aoStrCatFmt(ctx->buf, "cbnz x0, .LPHI%u\n\t", true_copy_label);
            aarch64EmitPhiCopiesForEdge(ctx, false_block, cur_block);
            aoStrCatFmt(ctx->buf, "b .LB%u\n", false_block->id);
            aoStrCatFmt(ctx->buf, ".LPHI%u:\n\t", true_copy_label);
            aarch64EmitPhiCopiesForEdge(ctx, true_block, cur_block);
            aoStrCatFmt(ctx->buf, "b .LB%u\n\t", true_block->id);
            break;
        }

        case IR_LOOP:
        case IR_JMP: {
            IrBlock *target = instr->extra.blocks.target_block;
            aarch64EmitPhiCopiesForEdge(ctx, target, cur_block);
            aoStrCatFmt(ctx->buf, "b .LB%u\n\t", target->id);
            break;
        }

        case IR_SWITCH: {
            IrBlock *default_block = instr->extra.blocks.target_block;
            if (!default_block || !instr->dst) {
                loggerPanic("AArch64 backend: malformed IR_SWITCH\n");
                break;
            }

            aarch64LoadIntValue(ctx, instr->dst, 0);
            if (instr->extra.cases) {
                listForEach(instr->extra.cases) {
                    IrPair *pair = listValue(IrPair *, it);
                    if (!pair || !pair->ir_block || !pair->ir_value) continue;
                    u32 next_case_label = ctx->current_label_id++;
                    aarch64LoadIntValue(ctx, pair->ir_value, 1);
                    aoStrCatFmt(ctx->buf, "cmp x0, x1\n\t");
                    aoStrCatFmt(ctx->buf, "b.ne .LSW%u\n\t", next_case_label);
                    aarch64EmitPhiCopiesForEdge(ctx, pair->ir_block, cur_block);
                    aoStrCatFmt(ctx->buf, "b .LB%u\n", pair->ir_block->id);
                    aoStrCatFmt(ctx->buf, ".LSW%u:\n\t", next_case_label);
                }
            }

            aarch64EmitPhiCopiesForEdge(ctx, default_block, cur_block);
            aoStrCatFmt(ctx->buf, "b .LB%u\n\t", default_block->id);
            break;
        }
        case IR_PHI:
            break;
        default:
            loggerPanic("AArch64 backend: unknown IR op `%s`\n",
                    irOpcodeToString(instr));
            break;
    }
}

void aarch64EmitFunction(AArch64Ctx *ctx, IrFunction *func) {
    AoStr *func_name = aarch64NormaliseFunctionName(func->name);
    aoStrCatFmt(ctx->buf, ".text\n"
                          ".globl %S\n"
                          "%S:\n\t", func_name, func_name);
    aoStrRelease(func_name);

    setRelease(ctx->alloca_tmps);
    ctx->alloca_tmps = setNew(64, &set_uint_type);

    u32 required_stack_size = 0;
    Map *extra_tmps = mapNew(32, &map_uint_to_uint_type);
    MapIter var_it;
    mapIterInit(func->variables, &var_it);
    while (mapIterNext(&var_it)) {
        IrValue *val = var_it.node->value;
        if (!val) continue;
        u32 var_size = (u32)alignTo((int)val->as.var.size, 8);
        required_stack_size += var_size;
    }

    listForEach(func->blocks) {
        IrBlock *block = listValue(IrBlock *, it);
        listForEach(block->instructions) {
            IrInstr *instr = listValue(IrInstr *, it);
            if (instr->op == IR_ALLOCA &&
                instr->dst &&
                instr->dst->kind == IR_VAL_TMP) {
                setAdd(ctx->alloca_tmps, (void *)(u64)instr->dst->as.var.id);
            }
            IrValue *candidates[3] = { instr->dst, instr->r1, instr->r2 };
            for (int i = 0; i < 3; ++i) {
                IrValue *val = candidates[i];
                if (!val || val->kind != IR_VAL_TMP) continue;
                u32 id = val->as.var.id;
                if (mapHasInt(func->variables, id) || mapHasInt(extra_tmps, id)) continue;
                u32 raw_size = val->as.var.size ? val->as.var.size : 8;
                u32 var_size = (u32)alignTo((int)raw_size, 8);
                mapAddIntOrErr(extra_tmps, id, (void *)(u64)var_size);
                required_stack_size += var_size;
            }
        }
    }

    u32 local_stack_size = (u32)alignTo((int)required_stack_size, 16);
    ctx->stack_size = local_stack_size;
    ctx->return_label_id = ctx->current_label_id++;

    aoStrCatFmt(ctx->buf, "stp x29, x30, [sp, #-16]!\n\t");
    aoStrCatFmt(ctx->buf, "mov x29, sp\n\t");
    aarch64AdjustSp(ctx, 0, local_stack_size);

    u32 stack_offset = local_stack_size;

    MapIter it;
    mapIterInit(func->variables, &it);
    while (mapIterNext(&it)) {
        IrValue *val = it.node->value;
        IrVar *var = &val->as.var;
        u32 var_size = (u32)alignTo((int)var->size, 8);
        stack_offset -= var_size;
        aarch64CtxSetVarOffset(ctx, var->id, stack_offset);
    }

    mapIterInit(extra_tmps, &it);
    while (mapIterNext(&it)) {
        u32 id = (u32)(u64)it.node->key;
        u32 var_size = (u32)(u64)it.node->value;
        stack_offset -= var_size;
        aarch64CtxSetVarOffset(ctx, id, stack_offset);
    }
    mapRelease(extra_tmps);

    u32 gp_reg = 0;
    u32 fp_reg = 0;
    u32 stack_param_offset = 0;
    for (u64 i = 0; i < func->params->size; ++i) {
        IrValue *param = func->params->entries[i];
        if (aarch64IsFloatType(param->type)) {
            if (fp_reg < 8) {
                aarch64StoreFloatValue(ctx, param, fp_reg);
                fp_reg++;
            } else {
                u32 incoming_offset = (u32)local_stack_size + 16 + stack_param_offset;
                aarch64AddStackOffset(ctx, 14, 15, incoming_offset);
                aoStrCatFmt(ctx->buf, "ldr d15, [x14]\n\t");
                aarch64StoreFloatValue(ctx, param, 15);
                stack_param_offset += 8;
            }
        } else {
            if (gp_reg < 8) {
                aarch64StoreIntValue(ctx, param, gp_reg);
                gp_reg++;
            } else {
                u32 incoming_offset = (u32)local_stack_size + 16 + stack_param_offset;
                aarch64AddStackOffset(ctx, 14, 15, incoming_offset);
                aoStrCatFmt(ctx->buf, "ldr x15, [x14]\n\t");
                aarch64StoreIntValue(ctx, param, 15);
                stack_param_offset += 8;
            }
        }
    }

    aoStrCatFmt(ctx->buf, "b .LB%u\n\t", func->entry_block->id);

    listForEach(func->blocks) {
        IrBlock *block = listValue(IrBlock *, it);
        int emitted_terminator = 0;
        if (ctx->buf->data[ctx->buf->len - 1] == '\t') {
            ctx->buf->len--;
        }
        aoStrCatFmt(ctx->buf, ".LB%u:\n\t", block->id);

        listForEach(block->instructions) {
            IrInstr *instr = listValue(IrInstr *, it);
            IrInstr *next_instr = NULL;
            if (it->next != block->instructions) {
                next_instr = listValue(IrInstr *, it->next);
            }
            /* While generating assembly we may have also nuked 
             * some instructions */
            if (instr->op == IR_NOP) continue;
            aarch64GenInstr(ctx, instr, next_instr, block);
            emitted_terminator = instr->op == IR_RET ||
                                 instr->op == IR_BR ||
                                 instr->op == IR_JMP ||
                                 instr->op == IR_LOOP ||
                                 instr->op == IR_SWITCH;
        }

        /* IR exit blocks are often intentionally empty and rely on an
         * explicit jump to the shared function epilogue. */
        if (!emitted_terminator) {
            Map *successors = irBlockGetSuccessors(func, block);
            if (!successors || successors->size == 0) {
                aoStrCatFmt(ctx->buf, "b .Lret%u\n\t", ctx->return_label_id);
            }
        }
    }

    if (ctx->buf->data[ctx->buf->len - 1] == '\t') {
        ctx->buf->len--;
    }
    aoStrCatFmt(ctx->buf, ".Lret%u:\n\t", ctx->return_label_id);
    if (func->return_value && func->return_value->type != IR_TYPE_VOID) {
        if (aarch64IsFloatType(func->return_value->type)) {
            aarch64LoadFloatValue(ctx, func->return_value, 0);
        } else {
            aarch64LoadIntValue(ctx, func->return_value, 0);
        }
    }
    aarch64AdjustSp(ctx, 1, local_stack_size);
    aoStrCatFmt(ctx->buf, "ldp x29, x30, [sp], #16\n\t");
    aoStrCatFmt(ctx->buf, "ret\n\t");
}

AoStr *aarch64GenCode(IrCtx *ir_ctx) {
    IrProgram *program = ir_ctx->prog;
    AArch64Ctx *ctx = aarch64CtxNew(program);
    aarch64CollectConstStrings(ctx, program);
    aarch64EmitConstStrings(ctx);
    aarch64EmitGlobals(ctx);
    for (u64 i = 0; i < program->functions->size; ++i) {
        IrFunction *func = program->functions->entries[i];
        aarch64EmitFunction(ctx, func);
    }
    AoStr *buf = ctx->buf;
    aarch64CtxRelease(ctx);
    return buf;
}

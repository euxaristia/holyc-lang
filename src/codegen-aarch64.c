#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "aostr.h"
#include "ir-debug.h"
#include "ir-types.h"
#include "util.h"

typedef struct AArch64Ctx {
    u16 stack_size;
    u16 current_label_id;
    u16 return_label_id;
    AoStr *buf;
    IrProgram *ir_program;
    Map *var_offsets;
    Set *registers;
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
            switch (value->type) {
                case IR_TYPE_I8:
                    aoStrCatFmt(ctx->buf, "ldrb w%u, [sp, #%u]\n\t", reg, offset);
                    return;
                case IR_TYPE_I16:
                    aoStrCatFmt(ctx->buf, "ldrh w%u, [sp, #%u]\n\t", reg, offset);
                    return;
                case IR_TYPE_I32:
                    aoStrCatFmt(ctx->buf, "ldr w%u, [sp, #%u]\n\t", reg, offset);
                    return;
                case IR_TYPE_I64:
                case IR_TYPE_PTR:
                case IR_TYPE_ARRAY:
                case IR_TYPE_ARRAY_INIT:
                case IR_TYPE_STRUCT:
                case IR_TYPE_FUNCTION:
                case IR_TYPE_ASM_FUNCTION:
                case IR_TYPE_LABEL:
                    aoStrCatFmt(ctx->buf, "ldr x%u, [sp, #%u]\n\t", reg, offset);
                    return;
                case IR_TYPE_F64:
                    aoStrCatFmt(ctx->buf, "ldr d15, [sp, #%u]\n\t", offset);
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
            loggerWarning("AArch64: global value missing symbol, using 0\n");
            aoStrCatFmt(ctx->buf, "mov x%u, #0\n\t", reg);
            return;
        case IR_VAL_CONST_STR:
            aoStrCatFmt(ctx->buf, "adrp x%u, %S\n\t", reg, value->as.str.label);
            aoStrCatFmt(ctx->buf, "add x%u, x%u, :lo12:%S\n\t",
                        reg, reg, value->as.str.label);
            return;
        case IR_VAL_PHI:
        case IR_VAL_LABEL:
        case IR_VAL_UNDEFINED:
        case IR_VAL_UNRESOLVED:
            loggerWarning("AArch64: unhandled int value kind `%s`, using 0\n",
                    irValueKindToString(value->kind));
            aoStrCatFmt(ctx->buf, "mov x%u, #0\n\t", reg);
            return;
    }
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
    switch (dest->type) {
        case IR_TYPE_I8:
            aoStrCatFmt(ctx->buf, "strb w%u, [sp, #%u]\n\t", reg, offset);
            return;
        case IR_TYPE_I16:
            aoStrCatFmt(ctx->buf, "strh w%u, [sp, #%u]\n\t", reg, offset);
            return;
        case IR_TYPE_I32:
            aoStrCatFmt(ctx->buf, "str w%u, [sp, #%u]\n\t", reg, offset);
            return;
        case IR_TYPE_I64:
        case IR_TYPE_PTR:
        case IR_TYPE_ARRAY:
        case IR_TYPE_ARRAY_INIT:
        case IR_TYPE_STRUCT:
        case IR_TYPE_FUNCTION:
        case IR_TYPE_ASM_FUNCTION:
        case IR_TYPE_LABEL:
            aoStrCatFmt(ctx->buf, "str x%u, [sp, #%u]\n\t", reg, offset);
            return;
        case IR_TYPE_F64:
            aoStrCatFmt(ctx->buf, "fmov d15, x%u\n\t", reg);
            aoStrCatFmt(ctx->buf, "str d15, [sp, #%u]\n\t", offset);
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
            aoStrCatFmt(ctx->buf, "ldr d%u, [sp, #%u]\n\t", reg, offset);
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
            loggerWarning("AArch64: unhandled float value kind `%s`, using 0.0\n",
                    irValueKindToString(value->kind));
            aoStrCatFmt(ctx->buf, "fmov d%u, xzr\n\t", reg);
            return;
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
    aoStrCatFmt(ctx->buf, "str d%u, [sp, #%u]\n\t", reg, offset);
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
                aoStrCatFmt(ctx->buf, "sub sp, sp, #%u\n\t", call_stack_size);
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
                        aoStrCatFmt(ctx->buf, "str d15, [sp, #%u]\n\t", stack_offset);
                        stack_offset += 8;
                    }
                } else {
                    if (gp_reg < 8) {
                        aarch64LoadIntValue(ctx, arm, gp_reg);
                        gp_reg++;
                    } else {
                        aarch64LoadIntValue(ctx, arm, 9);
                        aoStrCatFmt(ctx->buf, "str x9, [sp, #%u]\n\t", stack_offset);
                        stack_offset += 8;
                    }
                }
            }

            aoStrCatFmt(ctx->buf, "bl %S\n\t", args->label);
            if (call_stack_size) {
                aoStrCatFmt(ctx->buf, "add sp, sp, #%u\n\t", call_stack_size);
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

        case IR_ZEXT:
        case IR_SEXT: {
            aarch64LoadIntValue(ctx, instr->r1, 0);
            aoStrCatFmt(ctx->buf, "mov x8, x0\n\t");
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

        case IR_SWITCH:
        case IR_PHI:
            break;
        case IR_SELECT:
        case IR_VA_ARG:
        case IR_VA_START:
        case IR_VA_END:
        default:
            loggerWarning("AArch64: unhandled op `%s`, emitting nop-equivalent\n",
                    irOpcodeToString(instr));
            break;
    }
}

void aarch64EmitFunction(AArch64Ctx *ctx, IrFunction *func) {
    aoStrCatFmt(ctx->buf, ".globl %S\n"
                          "%S:\n\t", func->name, func->name);

    u16 local_stack_size = (u16)alignTo(func->stack_space, 16);
    ctx->stack_size = local_stack_size;
    ctx->return_label_id = ctx->current_label_id++;

    aoStrCatFmt(ctx->buf, "stp x29, x30, [sp, #-16]!\n\t");
    aoStrCatFmt(ctx->buf, "mov x29, sp\n\t");
    if (local_stack_size) {
        aoStrCatFmt(ctx->buf, "sub sp, sp, #%u\n\t", local_stack_size);
    }

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
                aoStrCatFmt(ctx->buf, "ldr d15, [sp, #%u]\n\t", incoming_offset);
                aarch64StoreFloatValue(ctx, param, 15);
                stack_param_offset += 8;
            }
        } else {
            if (gp_reg < 8) {
                aarch64StoreIntValue(ctx, param, gp_reg);
                gp_reg++;
            } else {
                u32 incoming_offset = (u32)local_stack_size + 16 + stack_param_offset;
                aoStrCatFmt(ctx->buf, "ldr x15, [sp, #%u]\n\t", incoming_offset);
                aarch64StoreIntValue(ctx, param, 15);
                stack_param_offset += 8;
            }
        }
    }

    aoStrCatFmt(ctx->buf, "b .LB%u\n\t", func->entry_block->id);

    listForEach(func->blocks) {
        IrBlock *block = listValue(IrBlock *, it);
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
        }
    }

    if (ctx->buf->data[ctx->buf->len - 1] == '\t') {
        ctx->buf->len--;
    }
    aoStrCatFmt(ctx->buf, ".Lret%u:\n\t", ctx->return_label_id);
    if (local_stack_size) {
        aoStrCatFmt(ctx->buf, "add sp, sp, #%u\n\t", local_stack_size);
    }
    aoStrCatFmt(ctx->buf, "ldp x29, x30, [sp], #16\n\t");
    aoStrCatFmt(ctx->buf, "ret\n\t");
}

AoStr *aarch64GenCode(IrCtx *ir_ctx) {
    IrProgram *program = ir_ctx->prog;
    AArch64Ctx *ctx = aarch64CtxNew(program);
    aarch64CollectConstStrings(ctx, program);
    aarch64EmitConstStrings(ctx);
    for (u64 i = 0; i < program->functions->size; ++i) {
        IrFunction *func = program->functions->entries[i];
        aarch64EmitFunction(ctx, func);
    }
    AoStr *buf = ctx->buf;
    aarch64CtxRelease(ctx);
    return buf;
}

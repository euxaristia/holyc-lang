#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "arena.h"
#include "ast.h"
#include "ir.h"
#include "ir-types.h"
#include "ir-debug.h"
#include "util.h"

static Arena ir_arena;
static int ir_arena_init = 0;
#define IR_VALUE_FLAG_ADDRESS (1ULL << 0)
#define IR_VALUE_FLAG_DEREF   (1ULL << 1)

void irMemoryInit(void) {
    if (!ir_arena_init) {
        /* @TODO; correct the size of the arena */
        arenaInit(&ir_arena, 512);
        ir_arena_init = 1;
    }
}

void irMemoryRelease(void) {
    if (ir_arena_init) {
        ir_arena_init = 0;
        arenaClear(&ir_arena);
    }
}

void *irAlloc(u32 size) {
    return arenaAlloc(&ir_arena, size);
}

void irMemoryStats(void) {
    printf("ir Arena:\n");
    arenaPrintStats(&ir_arena);
}

void vecIrFunctionToString(AoStr *buf, void *_ir_func) {
    IrFunction *ir_func = _ir_func;
    aoStrCatPrintf(buf, "%s", ir_func->name->data);
}

/* `Vec<IrFunction *>`*/
VecType vec_ir_function_type = {
    .stringify = vecIrFunctionToString,
    .match     = NULL,
    .release   = NULL,
    .type_str  = "IrFunction *",
};

Vec *irFunctionVecNew(void) {
    return vecNew(&vec_ir_function_type);
}

void vecIrPairToString(AoStr *buf, void *_ir_pair) {
    irPairToString(buf, _ir_pair);
}

/* `Vec<IrPair *>`*/
VecType vec_ir_pair_type = {
    .stringify = vecIrPairToString,
    .match     = NULL,
    .release   = NULL,
    .type_str  = "IrPair *",
};

Vec *irPairVecNew(void) {
    return vecNew(&vec_ir_pair_type);
}

void vecIrValueToString(AoStr *buf, void *_ir_value) {
    AoStr *ir_value_str = irValueToString(_ir_value);
    aoStrCatAoStr(buf, ir_value_str);
    aoStrRelease(ir_value_str);
}

/* `Vec<IrValue *>`*/
VecType vec_ir_value_type = {
    .stringify = vecIrValueToString,
    .match     = NULL,
    .release   = NULL,
    .type_str  = "IrValue *",
};

Vec *irValueVecNew(void) {
    return vecNew(&vec_ir_value_type);
}

AoStr *mapIrBlockToString(void *_ir_block) {
    IrBlock *ir_block = (IrBlock *)_ir_block;
    return aoStrPrintf("block %u", ir_block->id);
}

MapType map_u32_to_ir_block_type = {
    .match           = mapIntKeyMatch,
    .hash            = mapIntKeyHash,
    .get_key_len     = mapIntKeyLen,
    .key_to_string   = mapIntToString,
    .key_release     = NULL,
    .value_to_string = mapIrBlockToString,
    .value_release   = NULL,
    .key_type        = "u32",
    .value_type      = "IrBlock *",
};

Map *irBlockMapNew(void) {
    return mapNew(8, &map_u32_to_ir_block_type);
}

AoStr *mapIrBlockMappingToString(void *_ir_block_mapping) {
    IrBlockMapping *mapping = _ir_block_mapping;
    AoStr *str = aoStrNew();
    AoStr *preds = mapKeysToString(mapping->predecessors);
    AoStr *succ = mapKeysToString(mapping->successors);
    aoStrCatFmt(str, "predecessors: %S, successors: %S", preds, succ);
    aoStrRelease(preds);
    aoStrRelease(succ);
    return str;
}

void irBlockMappingRelease(void *_mapping) {
    IrBlockMapping *mapping = _mapping;
    mapRelease(mapping->predecessors);
    mapRelease(mapping->successors);
    
}

AoStr *mapIrValueToString(void *ir_value) {
    return irValueToString((IrValue *)ir_value);
}

/* `Map<u32, IrValue *>`*/
MapType map_u32_to_ir_var_value_type = {
    .match           = mapIntKeyMatch,
    .hash            = mapIntKeyHash,
    .get_key_len     = mapIntKeyLen,
    .key_to_string   = mapIntToString,
    .key_release     = NULL,
    .value_to_string = mapIrValueToString,
    .value_release   = NULL,
    .key_type        = "u32",
    .value_type      = "IrValue *",
};

/* `Map<u32, IrBlockMapping *>`*/
MapType map_u32_to_ir_block_mapping_type = {
    .match           = mapIntKeyMatch,
    .hash            = mapIntKeyHash,
    .get_key_len     = mapIntKeyLen,
    .key_to_string   = mapIntToString,
    .key_release     = NULL,
    .value_to_string = mapIrBlockMappingToString,
    .value_release   = NULL,
    .key_type        = "u32",
    .value_type      = "IrBlockMapping *",
};

Map *irBlockMappingMapNew(void) {
    return mapNew(32, &map_u32_to_ir_block_mapping_type);
}


IrBlockMapping *irBlockMappingNew(int id) {
    IrBlockMapping *mapping = (IrBlockMapping *)irAlloc(sizeof(IrBlockMapping));
    mapping->id = id;
    mapping->successors = irBlockMappingMapNew();
    mapping->predecessors = irBlockMappingMapNew();
    return mapping;
}

Map *irVarValueMap(void) {
    return mapNew(8, &map_u32_to_ir_var_value_type);
}

/* Pass in the whole block to abstract away that we area using an interal 
 * datastructure to keep track of things. I'm trying a few different ones out */
void irFunctionAddSuccessor(IrFunction *func, IrBlock *src, IrBlock *dest) {
    IrBlockMapping *ir_block_mapping = (IrBlockMapping *)mapGetInt(func->cfg, src->id);
    if (!ir_block_mapping) {
        ir_block_mapping = irBlockMappingNew(src->id);
        mapAddIntOrErr(func->cfg, src->id, ir_block_mapping);
    }
    mapAddIntOrErr(ir_block_mapping->successors, dest->id, dest);
}

void irFunctionAddPredecessor(IrFunction *func, IrBlock *src, IrBlock *prev) {
    IrBlockMapping *ir_block_mapping = (IrBlockMapping *)mapGetInt(func->cfg, src->id);
    if (!ir_block_mapping) {
        ir_block_mapping = irBlockMappingNew(src->id);
        mapAddIntOrErr(func->cfg, src->id, ir_block_mapping);
    }
    mapAddIntOrErr(ir_block_mapping->predecessors, prev->id, prev);
}

void irFunctionRemoveSuccessor(IrFunction *func, IrBlock *src, IrBlock *dest) {
    IrBlockMapping *ir_block_mapping = (IrBlockMapping *)mapGetInt(func->cfg, src->id);
    if (ir_block_mapping) {
        mapRemoveInt(ir_block_mapping->successors, dest->id);
    }
}

void irFunctionRemovePredecessor(IrFunction *func, IrBlock *src, IrBlock *prev) {
    IrBlockMapping *ir_block_mapping = (IrBlockMapping *)mapGetInt(func->cfg, src->id);
    if (ir_block_mapping) {
        mapRemoveInt(ir_block_mapping->predecessors, prev->id);
    }
}

void irFunctionAddMapping(IrFunction *func, IrBlock *src, IrBlock *dest) {
    irFunctionAddSuccessor(func, src, dest);
    irFunctionAddPredecessor(func, dest, src);
}

static u32 ir_block_id = 1;

void irResetBlockId(void) {
    ir_block_id = 1;
}

IrBlock *irBlockNew(void) {
    IrBlock *block = irAlloc(sizeof(IrBlock));
    block->instructions = listNew();
    block->removed = 0;
    block->sealed = 0;
    block->id = ir_block_id++;
    return block;
}

void irBlockRelease(IrBlock *block) {
    listRelease(block->instructions, NULL);
}

IrValue *irValueNew(IrValueType type, IrValueKind kind) {
    IrValue *val = irAlloc(sizeof(IrValue));
    memset(val, 0, sizeof(IrValue));
    val->kind = kind;
    val->type = type;
    return val;
}

static u32 ir_tmp_var_id = 0x70000000u;
void irTmpVariableCountReset(void) {
    ir_tmp_var_id = 0x70000000u;
}

IrValue *irTmp(IrValueType type, u16 size) {
    IrValue *val = irValueNew(type, IR_VAL_TMP);
    val->as.var.id = ir_tmp_var_id++;
    val->as.var.size = size;
    return val;
}

IrCtx *irCtxNew(Cctrl *cc) {
    IrCtx *ctx = malloc(sizeof(IrCtx));
    ctx->prog = malloc(sizeof(IrProgram));
    ctx->prog->functions = irFunctionVecNew();
    ctx->prog->globals = irValueVecNew();
    ctx->cc = cc;
    ctx->label_blocks = NULL;
    ctx->break_targets = listNew();
    ctx->continue_targets = listNew();
    return ctx;
}

static void irPushBreakTarget(IrCtx *ctx, IrBlock *target) {
    if (ctx && ctx->break_targets) listAppend(ctx->break_targets, target);
}

static void irPushContinueTarget(IrCtx *ctx, IrBlock *target) {
    if (ctx && ctx->continue_targets) listAppend(ctx->continue_targets, target);
}

static IrBlock *irCurrentBreakTarget(IrCtx *ctx) {
    if (!ctx || !ctx->break_targets || listEmpty(ctx->break_targets)) return NULL;
    return (IrBlock *)listHead(ctx->break_targets);
}

static IrBlock *irCurrentContinueTarget(IrCtx *ctx) {
    if (!ctx || !ctx->continue_targets || listEmpty(ctx->continue_targets)) return NULL;
    return (IrBlock *)listHead(ctx->continue_targets);
}

static void irPopBreakTarget(IrCtx *ctx) {
    if (ctx && ctx->break_targets && !listEmpty(ctx->break_targets)) {
        (void)listPop(ctx->break_targets);
    }
}

static void irPopContinueTarget(IrCtx *ctx) {
    if (ctx && ctx->continue_targets && !listEmpty(ctx->continue_targets)) {
        (void)listPop(ctx->continue_targets);
    }
}

void irCtxAddFunction(IrCtx *ctx, IrFunction *func) {
    vecPush(ctx->prog->functions, func);
}

IrInstr *irInstrNew(IrOp op, IrValue *dst, IrValue *r1, IrValue *r2) {
    IrInstr *instr = irAlloc(sizeof(IrInstr));
    memset(instr, 0, sizeof(IrInstr));
    instr->flags = 0;
    instr->op = op;
    instr->dst = dst;
    instr->r1 = r1;
    instr->r2 = r2;
    return instr;
}

IrFunction *irFunctionNew(AoStr *fname) {
    IrFunction *func = irAlloc(sizeof(IrFunction));
    func->name = fname;
    func->blocks = listNew();
    func->cfg = irBlockMappingMapNew();
    func->variables = irVarValueMap();
    func->stack_space = 0;
    func->params = irValueVecNew();
    func->has_var_args = 0;
    return func;
}

/* Map an ast id to an ir variable */
void irFnAddVar(IrFunction *func, u32 lvar_id, IrValue *var) {
    int ok = mapAddIntOrErr(func->variables, lvar_id, var);
    if (!ok) {
        AoStr *ir_value_str = irValueToString(var);
        loggerPanic("Mapping exists for %u -> %s", lvar_id, ir_value_str->data);
        free(ir_value_str);
    }
}

void irFnAddBlock(IrFunction *fn, IrBlock *block) {
    listAppend(fn->blocks, block);
}

static u32 irAstVarKey(Ast *ast_var) {
    if (!ast_var) return 0;
    switch (ast_var->kind) {
        case AST_LVAR:
            return ast_var->lvar_id;
        case AST_FUNPTR:
            return ast_var->fn_ptr_id;
        case AST_DEFAULT_PARAM:
            if (ast_var->declvar) return irAstVarKey(ast_var->declvar);
            return 0;
        default:
            return 0;
    }
}

IrValue *irFnGetVar(IrFunction *func, u32 lvar_id) {
    return mapGetInt(func->variables, lvar_id);
}

int irSetVariable(IrFunction *func, u32 var_id, IrValue *var) {
    return mapAddIntOrErr(func->variables, var_id, var);
}

void irFunctionRelease(IrFunction *func) {
    listRelease(func->blocks, (void (*)(void *))&irBlockRelease);
    mapRelease(func->cfg);
}

void irAddStackSpace(IrCtx *ctx, int size) {
    ctx->cur_func->stack_space += size;
}

void irBlockAddInstr(IrCtx *ctx, IrInstr *instr) {
    listAppend(ctx->cur_block->instructions, instr);
}

IrValue *irConstInt(IrValueType type, s64 i64) {
    IrValue *ir_value = irValueNew(type, IR_VAL_CONST_INT);
    ir_value->as._i64 = i64;
    return ir_value;
}

IrValue *irConstFloat(IrValueType type, f64 _f64) {
    IrValue *ir_value = irValueNew(type, IR_VAL_CONST_FLOAT);
    ir_value->as._f64 = _f64;
    return ir_value;
}

IrInstr *irAlloca(AstType *ast_type) {
    IrValueType ir_type = irConvertType(ast_type);
    IrValue *ir_size = irConstInt(ir_type, ast_type->size);
    IrValue *tmp = irTmp(ir_type, ast_type->size);
    IrInstr *ir_alloca = irInstrNew(IR_ALLOCA, tmp, ir_size, NULL);
    return ir_alloca;
}

IrInstr *irICmp(IrValue *result,
                IrCmpKind kind,
                IrValue *op1, 
                IrValue *op2)
{
    if (op1->type == IR_TYPE_PTR || op2->type == IR_TYPE_PTR) {
        if      (kind == IR_CMP_LT) kind = IR_CMP_ULT;
        else if (kind == IR_CMP_LE) kind = IR_CMP_ULE;
        else if (kind == IR_CMP_GT) kind = IR_CMP_UGT;
        else if (kind == IR_CMP_GE) kind = IR_CMP_UGE;
    }

    IrInstr *instr = irInstrNew(IR_ICMP, result, op1, op2);
    instr->extra.cmp_kind = kind;
    return instr;
}

IrInstr *irBranch(IrFunction *func,
                  IrBlock *block,
                  IrValue *cond,
                  IrBlock *true_block,
                  IrBlock *false_block)
{
    if (!block || !cond || !true_block || !false_block) {
        loggerPanic("irBranch: NULL parameter provided\n");
    }

    if (block->sealed) {
        return NULL;
    }

    if (cond->type != IR_TYPE_I8) {
        IrValue *zero = irConstInt(IR_TYPE_I8, 0);
        IrValue *bool_cond = irTmp(IR_TYPE_I8, 1);
        IrInstr *cmp = irICmp(bool_cond, IR_CMP_NE, cond, zero);
        listAppend(block->instructions, cmp);
        cond = bool_cond;
    }

    IrInstr *instr = irInstrNew(IR_BR, cond, NULL, NULL);
    instr->extra.blocks.target_block = true_block;
    instr->extra.blocks.fallthrough_block = false_block;

    listAppend(block->instructions, instr);
    block->sealed = 1;

    irFunctionAddMapping(func, block, true_block);
    irFunctionAddMapping(func, block, false_block);

    return instr;
}

IrInstr *irJumpInternal(IrFunction *func,
                        IrBlock *block,
                        IrBlock *target,
                        IrOp opcode)
{
    if (!block || !target) {
        loggerPanic("NULL param\n");
    }
    if (block->sealed) {
        return NULL;
    }

    IrInstr *instr = irInstrNew(opcode, NULL, NULL, NULL);
    instr->extra.blocks.target_block = target;
    instr->extra.blocks.fallthrough_block = NULL;

    listAppend(block->instructions, instr);

    /* This block is done */
    block->sealed = 1;

    /* Now update the control flow graph */
    irFunctionAddMapping(func, block, target);

    return instr;
}

IrInstr *irJump(IrFunction *func, IrBlock *block, IrBlock *target) {
    return irJumpInternal(func, block,target,IR_JMP);
}

IrInstr *irLoop(IrFunction *func, IrBlock *block, IrBlock *target) {
    return irJumpInternal(func, block,target,IR_LOOP);
}

IrPair *irPairNew(IrBlock *ir_block, IrValue *ir_value) {
    IrPair *ir_phi_pair = (IrPair *)irAlloc(sizeof(IrPair));
    ir_phi_pair->ir_value = ir_value;
    ir_phi_pair->ir_block = ir_block;
    return ir_phi_pair;
}

IrInstr *irPhi(IrValue *result) {
    IrInstr *ir_phi_instr = irInstrNew(IR_PHI, result, NULL, NULL);
    ir_phi_instr->extra.phi_pairs = irPairVecNew();
    return ir_phi_instr;
}

void irAddPhiIncoming(IrInstr *ir_phi_instr,
                      IrValue *ir_value, 
                      IrBlock *ir_block)
{
    IrPair *ir_phi_pair = irPairNew(ir_block, ir_value);
    vecPush(ir_phi_instr->extra.phi_pairs, ir_phi_pair);
}


IrInstr *irLoad(IrValue *ir_dest, IrValue *ir_value) {
    return irInstrNew(IR_LOAD, ir_dest, ir_value, NULL);
}

/* result is where we are storing something and op1 is the thing we are storing 
 * I think op1 could/shoule have an offset as it is either going to be the 
 * stack or it is going to be a struct/pointer offset? */
IrInstr *irStore(IrValue *ir_dest, IrValue *ir_value) {
    return irInstrNew(IR_STORE, ir_dest, ir_value, NULL);
}

IrValue *irExpr(IrCtx *ctx, Ast *ast);
static IrValue *irExprAddress(IrCtx *ctx, Ast *ast);

static IrValue *irGlobalAddress(Ast *ast) {
    IrValue *global = irValueNew(IR_TYPE_PTR, IR_VAL_GLOBAL);
    if (ast->glabel) {
        global->as.global.name = ast->glabel;
    } else {
        global->as.global.name = ast->gname;
    }
    global->as.global.value = NULL;
    return global;
}

static IrValue *irFunctionAddress(Ast *ast) {
    IrValue *func = irValueNew(IR_TYPE_PTR, IR_VAL_GLOBAL);
    if (ast->kind == AST_ASM_FUNC_BIND && ast->asmfname) {
        func->as.global.name = ast->asmfname;
    } else {
        func->as.global.name = ast->fname;
    }
    func->as.global.value = NULL;
    return func;
}

static IrValue *irAddressView(IrValue *base) {
    if (!base) return NULL;
    IrValue *addr = irValueNew(base->type, base->kind);
    memcpy(addr, base, sizeof(IrValue));
    addr->flags |= IR_VALUE_FLAG_ADDRESS;
    return addr;
}

static IrValue *irDerefAddressView(IrValue *base) {
    IrValue *addr = irAddressView(base);
    if (addr) addr->flags |= IR_VALUE_FLAG_DEREF;
    return addr;
}

static void irCollectGlobal(IrCtx *ctx, Ast *declvar, Ast *declinit) {
    if (!declvar || declvar->kind != AST_GVAR) return;
    if (declvar->gname &&
        (!strcmp(declvar->gname->data, "argc") || !strcmp(declvar->gname->data, "argv"))) {
        return;
    }
    IrValue *global = irGlobalAddress(declvar);
    global->type = irConvertType(declvar->type);
    global->flags = (u64)(declvar->type ? declvar->type->size : 8);
    global->as.global.value = NULL;

    if (declinit) {
        if (declinit->kind == AST_LITERAL) {
            global->as.global.value = irConstInt(irConvertType(declinit->type), declinit->i64);
        } else if (declinit->kind == AST_STRING) {
            IrValue *strv = irValueNew(IR_TYPE_ARRAY, IR_VAL_CONST_STR);
            strv->as.str.label = declinit->slabel;
            strv->as.str.str = declinit->sval;
            strv->as.str.str_real_len = declinit->real_len;
            global->as.global.value = strv;
        }
    }

    vecPush(ctx->prog->globals, global);
}

static IrBlock *irGetOrCreateLabelBlock(IrCtx *ctx, AoStr *label) {
    if (!label) {
        loggerPanic("goto/label lowering: missing label\n");
    }
    IrBlock *block = mapGet(ctx->label_blocks, label->data);
    if (block) return block;

    block = irBlockNew();
    irFnAddBlock(ctx->cur_func, block);
    mapAdd(ctx->label_blocks, label->data, block);
    return block;
}

IrValue *irFnCall(IrCtx *ctx, Ast *ast) {
    IrValueType ret_type = irConvertType(ast->type);
    IrValue *ir_call_args = irValueNew(IR_TYPE_ARRAY, IR_VAL_UNRESOLVED);
    IrValue *ir_ret_val = irTmp(ret_type, ast->type->size);
    IrValue *call_target = NULL;
    IrInstr *ir_call_instr = irInstrNew(IR_CALL, ir_ret_val, ir_call_args, NULL);

    assert(ast->kind == AST_FUNCALL ||
           ast->kind == AST_ASM_FUNCALL ||
           ast->kind == AST_FUNPTR_CALL);

    Vec *args = irValueVecNew();
    ir_call_args->as.array.values = args;
    if (ast->kind == AST_FUNPTR_CALL) {
        call_target = irExpr(ctx, ast->ref);
        ir_call_args->as.array.label = NULL;
    } else {
        ir_call_args->as.array.label = ast->fname;
    }
    ir_call_instr->r2 = call_target;

    if (ast->args) {
        for (u64 i = 0; i < ast->args->size; ++i) {
            Ast *ast_arg = ast->args->entries[i];
            IrValue *ir_arg = irExpr(ctx, ast_arg);
            vecPush(args, ir_arg);
        }
    }

    irBlockAddInstr(ctx, ir_call_instr);
    return ir_ret_val;
}

static IrValue *irExprAddress(IrCtx *ctx, Ast *ast) {
    if (!ast) return NULL;
    switch (ast->kind) {
        case AST_LVAR: {
            IrValue *local = irFnGetVar(ctx->cur_func, ast->lvar_id);
            if (!local) {
                loggerPanic("Address lowering: variable not found (id=%u, fn=%s): %s\n",
                        ast->lvar_id,
                        ctx->cur_func && ctx->cur_func->name ? ctx->cur_func->name->data : "<unknown>",
                        astToString(ast));
            }
            return irAddressView(local);
        }
        case AST_FUNPTR: {
            IrValue *local = irFnGetVar(ctx->cur_func, ast->fn_ptr_id);
            if (!local) {
                loggerPanic("Address lowering: function pointer not found (id=%u, fn=%s): %s\n",
                        ast->fn_ptr_id,
                        ctx->cur_func && ctx->cur_func->name ? ctx->cur_func->name->data : "<unknown>",
                        astToString(ast));
            }
            return irAddressView(local);
        }
        case AST_UNOP:
            if (ast->unop == AST_UN_OP_DEREF) {
                IrValue *addr = irExpr(ctx, ast->operand);
                return irDerefAddressView(addr);
            }
            break;
        case AST_GVAR:
            return irGlobalAddress(ast);
        case AST_FUNC:
        case AST_FUN_PROTO:
        case AST_EXTERN_FUNC:
        case AST_ASM_FUNC_BIND:
            return irFunctionAddress(ast);
        case AST_CLASS_REF: {
            IrValue *base = NULL;
            int cls_is_ptr = ast->cls && ast->cls->type && astTypeIsPtr(ast->cls->type);
            int cls_is_deref_ptr = ast->cls &&
                                   ast->cls->kind == AST_UNOP &&
                                   ast->cls->unop == AST_UN_OP_DEREF;
            if (cls_is_deref_ptr && ast->cls->operand) {
                base = irExpr(ctx, ast->cls->operand);
                cls_is_ptr = 1;
            } else if (cls_is_ptr) {
                base = irExpr(ctx, ast->cls);
            } else {
                base = irExprAddress(ctx, ast->cls);
            }
            if (!base) {
                loggerPanic("Address lowering: class reference base is null\n");
            }
            int offset = ast->type ? ast->type->offset : 0;
            if (offset == 0) {
                if (cls_is_ptr) {
                    return irDerefAddressView(base);
                }
                return base;
            }

            IrValue *addr = irTmp(IR_TYPE_PTR, 8);
            addr->flags |= IR_VALUE_FLAG_ADDRESS;
            IrInstr *add = irInstrNew(IR_IADD, addr, base, irConstInt(IR_TYPE_I64, offset));
            irBlockAddInstr(ctx, add);
            return addr;
        }
        case AST_DEFAULT_PARAM:
            if (ast->declvar) {
                return irExprAddress(ctx, ast->declvar);
            }
            if (ast->declinit) {
                return irExprAddress(ctx, ast->declinit);
            }
            break;
        default:
            break;
    }
    return NULL;
}

static s64 irPointerStep(AstType *type) {
    if (type && astTypeIsPtr(type) && type->ptr && type->ptr->size > 0) {
        return type->ptr->size;
    }
    return 1;
}

/* Binary expressions are assumed to always be assigning to something. I'm not
 * 100% sure this is a valid assumption to make. Well I guess;
 * `I64 x = y + 32 * 10` _could_ continually be assigned to `x` */
IrValue *irBinOpExpr(IrCtx *ctx, Ast *ast) {
    IrValueType ir_type = irConvertType(ast->type);
    IrValue *ir_result = irTmp(ir_type, ast->type->size);
    IrOp op;
    IrCmpKind cmp = IR_CMP_INVALID;

    if (ast->binop == AST_BIN_OP_ASSIGN) {
        IrValue *rhs = irExpr(ctx, ast->right);
        IrValue *dst = NULL;
        if (ast->left->kind == AST_LVAR) {
            dst = irFnGetVar(ctx->cur_func, ast->left->lvar_id);
        } else if (ast->left->kind == AST_FUNPTR) {
            dst = irFnGetVar(ctx->cur_func, ast->left->fn_ptr_id);
        } else if (ast->left->kind == AST_GVAR) {
            dst = irExprAddress(ctx, ast->left);
        } else if (ast->left->kind == AST_CLASS_REF ||
                   (ast->left->kind == AST_UNOP && ast->left->unop == AST_UN_OP_DEREF)) {
            dst = irExprAddress(ctx, ast->left);
        } else {
            dst = irExpr(ctx, ast->left);
        }
        if (!dst) {
            loggerPanic("Assignment destination could not be lowered: %s\n",
                    astToString(ast->left));
        }
        if (ast->left && ast->left->type) {
            IrValueType lhs_type = irConvertType(ast->left->type);
            if (rhs && rhs->type != lhs_type) {
                IrValue *coerced = irTmp(lhs_type, ast->left->type->size);
                IrOp cast_op = IR_BITCAST;

                if (irIsInt(rhs->type) && irIsInt(lhs_type)) {
                    int src_size = irGetIntSize(rhs->type);
                    int dst_size = irGetIntSize(lhs_type);
                    if (src_size > dst_size) {
                        cast_op = IR_TRUNC;
                    } else if (src_size < dst_size) {
                        int src_signed = (ast->right && ast->right->type) ? ast->right->type->issigned : 0;
                        cast_op = src_signed ? IR_SEXT : IR_ZEXT;
                    }
                } else if (irIsFloat(rhs->type) && irIsFloat(lhs_type)) {
                    cast_op = IR_BITCAST;
                } else if (irIsFloat(rhs->type) && irIsInt(lhs_type)) {
                    cast_op = (ast->left->type && ast->left->type->issigned) ? IR_FPTOSI : IR_FPTOUI;
                } else if (irIsInt(rhs->type) && irIsFloat(lhs_type)) {
                    int src_signed = (ast->right && ast->right->type) ? ast->right->type->issigned : 0;
                    cast_op = src_signed ? IR_SITOFP : IR_UITOFP;
                } else if (rhs->type == IR_TYPE_PTR && irIsInt(lhs_type)) {
                    cast_op = IR_PTRTOINT;
                } else if (irIsInt(rhs->type) && lhs_type == IR_TYPE_PTR) {
                    cast_op = IR_INTTOPTR;
                }

                irBlockAddInstr(ctx, irInstrNew(cast_op, coerced, rhs, NULL));
                rhs = coerced;
            }
        }
        IrInstr *ir_store = irStore(dst, rhs);
        irBlockAddInstr(ctx, ir_store);
        return rhs;
    }

    if (ast->binop == AST_BIN_OP_LOG_AND) {
        IrBlock *ir_right_block = irBlockNew();
        IrBlock *ir_end_block = irBlockNew();

        IrValue *left = irExpr(ctx, ast->left);
        IrBlock *ir_block = ctx->cur_block;
        IrValue *ir_result = irTmp(IR_TYPE_I8, 1);

        irBranch(ctx->cur_func, ir_block, left, ir_right_block, ir_end_block);
        irFnAddBlock(ctx->cur_func, ir_right_block);
        ctx->cur_block = ir_right_block;

        IrValue *right = irExpr(ctx, ast->right);

        irJump(ctx->cur_func, ctx->cur_block, ir_end_block);
        irFnAddBlock(ctx->cur_func, ir_end_block);
        ctx->cur_block = ir_end_block;

        IrInstr *phi_instr = irPhi(ir_result);
        irBlockAddInstr(ctx, phi_instr);
        irAddPhiIncoming(phi_instr, irConstInt(IR_TYPE_I8, 0), ir_block);
        irAddPhiIncoming(phi_instr, right, ir_right_block);
        return ir_result;
    }

    if (ast->binop == AST_BIN_OP_LOG_OR) {
        IrBlock *ir_right_block = irBlockNew();
        IrBlock *ir_end_block = irBlockNew();

        IrValue *left = irExpr(ctx, ast->left);
        IrBlock *ir_block = ctx->cur_block;
        IrValue *ir_result = irTmp(IR_TYPE_I8, 1);

        /* For an OR the difference is this is switched around */
        irBranch(ctx->cur_func, ir_block, left, ir_end_block, ir_right_block);
        irFnAddBlock(ctx->cur_func, ir_right_block);
        ctx->cur_block = ir_right_block;

        IrValue *right = irExpr(ctx, ast->right);

        irJump(ctx->cur_func, ctx->cur_block, ir_end_block);
        irFnAddBlock(ctx->cur_func, ir_end_block);
        ctx->cur_block = ir_end_block;

        IrInstr *phi_instr = irPhi(ir_result);
        irBlockAddInstr(ctx, phi_instr);
        irAddPhiIncoming(phi_instr, irConstInt(IR_TYPE_I8, 1), ir_block);
        irAddPhiIncoming(phi_instr, right, ir_right_block);
        return ir_result;
    }

    IrValue *lhs = irExpr(ctx, ast->left);
    IrValue *rhs = irExpr(ctx, ast->right);

    /* Lower pointer arithmetic with explicit scaling while we still have AST types. */
    if ((ast->binop == AST_BIN_OP_ADD || ast->binop == AST_BIN_OP_SUB) &&
        ast->left && ast->right) {
        int lhs_is_ptr = astTypeIsPtr(ast->left->type);
        int rhs_is_ptr = astTypeIsPtr(ast->right->type);
        int lhs_is_int = astIsIntType(ast->left->type) || ast->left->type->kind == AST_TYPE_CHAR;
        int rhs_is_int = astIsIntType(ast->right->type) || ast->right->type->kind == AST_TYPE_CHAR;

        if (lhs_is_ptr && rhs_is_int) {
            int elem_size = 1;
            if (ast->left->type->ptr && ast->left->type->ptr->size > 0) {
                elem_size = ast->left->type->ptr->size;
            }
            if (elem_size > 1) {
                IrValue *scale = irConstInt(rhs->type, elem_size);
                IrValue *scaled = irTmp(rhs->type, 8);
                irBlockAddInstr(ctx, irInstrNew(IR_IMUL, scaled, rhs, scale));
                rhs = scaled;
            }
            IrInstr *ptr_math = irInstrNew(
                    ast->binop == AST_BIN_OP_ADD ? IR_IADD : IR_ISUB,
                    ir_result, lhs, rhs);
            irBlockAddInstr(ctx, ptr_math);
            return ir_result;
        }

        if (ast->binop == AST_BIN_OP_ADD && rhs_is_ptr && lhs_is_int) {
            int elem_size = 1;
            if (ast->right->type->ptr && ast->right->type->ptr->size > 0) {
                elem_size = ast->right->type->ptr->size;
            }
            if (elem_size > 1) {
                IrValue *scale = irConstInt(lhs->type, elem_size);
                IrValue *scaled = irTmp(lhs->type, 8);
                irBlockAddInstr(ctx, irInstrNew(IR_IMUL, scaled, lhs, scale));
                lhs = scaled;
            }
            IrInstr *ptr_math = irInstrNew(IR_IADD, ir_result, rhs, lhs);
            irBlockAddInstr(ctx, ptr_math);
            return ir_result;
        }
    }

    if (irIsFloat(ir_type)) {
        switch (ast->binop) {
            case AST_BIN_OP_ADD:
                op = IR_FADD;
                break;
            case AST_BIN_OP_MUL:
                op = IR_FMUL;
                break;
            case AST_BIN_OP_DIV:
                op = IR_FDIV;
                break;
            case AST_BIN_OP_SUB:
                op = IR_FSUB;
                break;
            case AST_BIN_OP_LT:
                op = IR_FCMP;
                cmp = IR_CMP_LT;
                break;
            case AST_BIN_OP_LE:
                op = IR_FCMP;
                cmp = IR_CMP_LE;
                break;
            case AST_BIN_OP_GT:
                op = IR_FCMP;
                cmp = IR_CMP_GT;
                break;
            case AST_BIN_OP_GE:
                op = IR_FCMP;
                cmp = IR_CMP_GE;
                break;
            case AST_BIN_OP_EQ:
                op = IR_FCMP;
                cmp = IR_CMP_EQ;
                break;
            case AST_BIN_OP_NE:
                op = IR_FCMP;
                cmp = IR_CMP_NE;
                break;
            default:
                loggerPanic("Op `%s` not handled for float \n",
                        astBinOpKindToString(ast->binop));
        }
    } else if (irIsInt(ir_type) || irIsPtr(ir_type)) {
        switch (ast->binop) {
            case AST_BIN_OP_ADD:
                op = IR_IADD;
                break;
            case AST_BIN_OP_MUL:
                op = IR_IMUL;
                break;
            case AST_BIN_OP_DIV:
                if (ast->type->issigned) {
                    op = IR_IDIV;
                } else {
                    op = IR_UDIV;
                }
                break;
            case AST_BIN_OP_MOD:
                if (ast->type->issigned) {
                    op = IR_IREM;
                } else {
                    op = IR_UREM;
                }
                break;
            case AST_BIN_OP_SUB:
                op = IR_ISUB;
                break;
            case AST_BIN_OP_SHL:
                op = IR_SHL;
                break;
            case AST_BIN_OP_SHR:
                if (ast->type->issigned) {
                    op = IR_SAR;
                } else {
                    op = IR_SHR;
                }
                break;
            case AST_BIN_OP_BIT_AND:
                op = IR_AND;
                break;
            case AST_BIN_OP_BIT_XOR:
                op = IR_XOR;
                break;
            case AST_BIN_OP_BIT_OR:
                op = IR_OR;
                break;
            case AST_BIN_OP_LT:
                op = IR_ICMP;
                if (irIsPtr(ir_type)) {
                    cmp = IR_CMP_ULT;
                } else if (ast->type->issigned) {
                    cmp = IR_CMP_LT;
                } else {
                    cmp = IR_CMP_ULT;
                }
                break;
            case AST_BIN_OP_LE:
                op = IR_ICMP;
                if (irIsPtr(ir_type)) {
                    cmp = IR_CMP_ULE;
                } else if (ast->type->issigned) {
                    cmp = IR_CMP_LE;
                } else {
                    cmp = IR_CMP_ULE;
                }
                break;
            case AST_BIN_OP_GT:
                op = IR_ICMP;
                if (irIsPtr(ir_type)) {
                    cmp = IR_CMP_UGT;
                } else if (ast->type->issigned) {
                    cmp = IR_CMP_GT;
                } else {
                    cmp = IR_CMP_UGT;
                }
                break;
            case AST_BIN_OP_GE:
                op = IR_ICMP;
                if (irIsPtr(ir_type)) {
                    cmp = IR_CMP_UGE;
                } else if (ast->type->issigned) {
                    cmp = IR_CMP_GE;
                } else {
                    cmp = IR_CMP_UGE;
                }
                break;
            case AST_BIN_OP_EQ:
                op = IR_ICMP;
                cmp = IR_CMP_EQ;
                break;
            case AST_BIN_OP_NE:
                op = IR_ICMP;
                cmp = IR_CMP_NE;
                break;
            default:
                loggerPanic("Op `%s` not handled for int: %s\n",
                        astBinOpKindToString(ast->binop),
                        astToString(ast));
        }
    } else {
        loggerPanic("Unhandled Ir type: %s\n", irValueTypeToString(ir_type));
    }
    IrInstr *instr = irInstrNew(op, ir_result, lhs, rhs);
    instr->extra.cmp_kind = cmp;
    irBlockAddInstr(ctx, instr);
    return ir_result;
}

IrValue *irExpr(IrCtx *ctx, Ast *ast) {
    switch (ast->kind) {
        case AST_BINOP:
            return irBinOpExpr(ctx, ast);
        case AST_LITERAL:
            switch (ast->type->kind) {
                case AST_TYPE_INT:
                case AST_TYPE_CHAR:
                    return irConstInt(irConvertType(ast->type), ast->i64);
                case AST_TYPE_FLOAT: {
                        IrValue *value = irConstFloat(IR_TYPE_F64, ast->f64);
                        // irAddConstFloat(ctx->ir_program, value);
                        return value;
                    }
                default:
                    loggerPanic("Unknown literal: %s\n",
                            astTypeKindToString(ast->type->kind));
            }
            break;
        case AST_LVAR: {
            IrValue *local_var = irFnGetVar(ctx->cur_func, ast->lvar_id);
            if (!local_var) {
                loggerPanic("Variable not found (id=%u, fn=%s): %s\n",
                        ast->lvar_id,
                        ctx->cur_func && ctx->cur_func->name ? ctx->cur_func->name->data : "<unknown>",
                        astToString(ast));
            }

            IrValueType ir_value_type = irConvertType(ast->type);
            if (local_var->type == IR_TYPE_ARRAY ||
                local_var->type == IR_TYPE_STRUCT ||
                irIsStruct(ir_value_type) ||
                ir_value_type == IR_TYPE_ARRAY) {
                return local_var;
            }

            IrValue *ir_load_dest = irTmp(ir_value_type, ast->type->size);
            IrInstr *load_instr = irLoad(ir_load_dest, local_var);
            irBlockAddInstr(ctx, load_instr);
            return ir_load_dest;
        }
        case AST_FUNPTR: {
            IrValue *local_var = irFnGetVar(ctx->cur_func, ast->fn_ptr_id);
            if (!local_var) {
                loggerPanic("Function pointer not found (id=%u, fn=%s): %s\n",
                        ast->fn_ptr_id,
                        ctx->cur_func && ctx->cur_func->name ? ctx->cur_func->name->data : "<unknown>",
                        astToString(ast));
            }

            IrValueType ir_value_type = irConvertType(ast->type);
            IrValue *ir_load_dest = irTmp(ir_value_type, ast->type->size);
            IrInstr *load_instr = irLoad(ir_load_dest, local_var);
            irBlockAddInstr(ctx, load_instr);
            return ir_load_dest;
        }

        case AST_FUNCALL:
        case AST_ASM_FUNCALL:
        case AST_FUNPTR_CALL:
            return irFnCall(ctx, ast);

        case AST_STRING: {
            IrValue *value = irValueNew(IR_TYPE_ARRAY, IR_VAL_CONST_STR);
            value->as.str.str = ast->sval;
            value->as.str.label = ast->slabel;
            value->as.str.str_real_len = ast->real_len;
            return value;
        }

        case AST_GVAR: {
            IrValue *global_addr = irGlobalAddress(ast);
            IrValueType ir_value_type = irConvertType(ast->type);
            if (irIsStruct(ir_value_type) || ir_value_type == IR_TYPE_ARRAY) {
                return global_addr;
            }
            IrValue *loaded = irTmp(ir_value_type, ast->type->size);
            IrInstr *load = irLoad(loaded, global_addr);
            irBlockAddInstr(ctx, load);
            return loaded;
        }

        case AST_UNOP: {
            IrValue *operand = NULL;
            switch (ast->unop) {
                case AST_UN_OP_PRE_INC: {
                    IrValue *addr = irExprAddress(ctx, ast->operand);
                    if (!addr) {
                        loggerPanic("IR lowering: pre-inc operand is not assignable\n");
                    }
                    IrValueType value_type = irConvertType(ast->operand->type);
                    u16 value_size = ast->operand->type ? ast->operand->type->size : 8;
                    IrValue *loaded = irTmp(value_type, value_size);
                    irBlockAddInstr(ctx, irLoad(loaded, addr));
                    IrValue *one = irConstInt(IR_TYPE_I64, irPointerStep(ast->operand->type));
                    IrValue *result = irTmp(value_type, value_size);
                    IrInstr *add = irInstrNew(IR_IADD, result, loaded, one);
                    irBlockAddInstr(ctx, add);
                    IrInstr *store = irStore(addr, result);
                    irBlockAddInstr(ctx, store);
                    return result;
                }
                case AST_UN_OP_POST_INC: {
                    IrValue *addr = irExprAddress(ctx, ast->operand);
                    if (!addr) {
                        loggerPanic("IR lowering: post-inc operand is not assignable (kind=%s): %s\n",
                                astKindToString(ast->operand->kind),
                                astToString(ast->operand));
                    }
                    IrValueType value_type = irConvertType(ast->operand->type);
                    u16 value_size = ast->operand->type ? ast->operand->type->size : 8;
                    IrValue *loaded = irTmp(value_type, value_size);
                    irBlockAddInstr(ctx, irLoad(loaded, addr));
                    IrValue *one = irConstInt(IR_TYPE_I64, irPointerStep(ast->operand->type));
                    IrValue *result = irTmp(value_type, value_size);
                    IrInstr *add = irInstrNew(IR_IADD, result, loaded, one);
                    irBlockAddInstr(ctx, add);
                    IrInstr *store = irStore(addr, result);
                    irBlockAddInstr(ctx, store);
                    return loaded;
                }
                case AST_UN_OP_PRE_DEC: {
                    IrValue *addr = irExprAddress(ctx, ast->operand);
                    if (!addr) {
                        loggerPanic("IR lowering: pre-dec operand is not assignable\n");
                    }
                    IrValueType value_type = irConvertType(ast->operand->type);
                    u16 value_size = ast->operand->type ? ast->operand->type->size : 8;
                    IrValue *loaded = irTmp(value_type, value_size);
                    irBlockAddInstr(ctx, irLoad(loaded, addr));
                    IrValue *one = irConstInt(IR_TYPE_I64, irPointerStep(ast->operand->type));
                    IrValue *result = irTmp(value_type, value_size);
                    IrInstr *sub = irInstrNew(IR_ISUB, result, loaded, one);
                    irBlockAddInstr(ctx, sub);
                    IrInstr *store = irStore(addr, result);
                    irBlockAddInstr(ctx, store);
                    return result;
                }
                case AST_UN_OP_POST_DEC: {
                    IrValue *addr = irExprAddress(ctx, ast->operand);
                    if (!addr) {
                        loggerPanic("IR lowering: post-dec operand is not assignable\n");
                    }
                    IrValueType value_type = irConvertType(ast->operand->type);
                    u16 value_size = ast->operand->type ? ast->operand->type->size : 8;
                    IrValue *loaded = irTmp(value_type, value_size);
                    irBlockAddInstr(ctx, irLoad(loaded, addr));
                    IrValue *one = irConstInt(IR_TYPE_I64, irPointerStep(ast->operand->type));
                    IrValue *result = irTmp(value_type, value_size);
                    IrInstr *sub = irInstrNew(IR_ISUB, result, loaded, one);
                    irBlockAddInstr(ctx, sub);
                    IrInstr *store = irStore(addr, result);
                    irBlockAddInstr(ctx, store);
                    return loaded;
                }
                case AST_UN_OP_MINUS: {
                    operand = irExpr(ctx, ast->operand);
                    IrValue *result = irTmp(IR_TYPE_I64, 8);
                    IrInstr *neg = irInstrNew(IR_INEG, result, operand, NULL);
                    irBlockAddInstr(ctx, neg);
                    return result;
                }
                case AST_UN_OP_LOG_NOT: {
                    operand = irExpr(ctx, ast->operand);
                    IrValue *zero = irConstInt(IR_TYPE_I8, 0);
                    IrValue *result = irTmp(IR_TYPE_I8, 1);
                    IrInstr *cmp = irICmp(result, IR_CMP_EQ, operand, zero);
                    irBlockAddInstr(ctx, cmp);
                    return result;
                }
                case AST_UN_OP_BIT_NOT: {
                    operand = irExpr(ctx, ast->operand);
                    IrValue *result = irTmp(IR_TYPE_I64, 8);
                    IrInstr *not = irInstrNew(IR_NOT, result, operand, NULL);
                    irBlockAddInstr(ctx, not);
                    return result;
                }
                case AST_UN_OP_ADDR_OF: {
                    IrValue *addr = irExprAddress(ctx, ast->operand);
                    if (!addr) {
                        loggerPanic("Address-of lowering failed for `%s`\n", astToString(ast->operand));
                    }
                    return addr;
                }
                case AST_UN_OP_DEREF: {
                    operand = irExpr(ctx, ast->operand);
                    IrValue *addr = irDerefAddressView(operand);
                    IrValueType result_type = irConvertType(ast->type);
                    IrValue *result = irTmp(result_type, ast->type->size);
                    IrInstr *load = irLoad(result, addr);
                    irBlockAddInstr(ctx, load);
                    return result;
                }
                default:
                    loggerPanic("Unhandled unary op: %d\n", ast->unop);
            }
        }

        case AST_CAST: {
            IrValue *operand = irExpr(ctx, ast->operand);
            IrValueType src_type = operand->type;
            IrValueType dst_type = irConvertType(ast->type);
            if (src_type == dst_type) {
                return operand;
            }

            IrValue *result = irTmp(dst_type, ast->type->size);
            IrOp op = IR_BITCAST;

            if (irIsInt(src_type) && irIsInt(dst_type)) {
                int src_size = irGetIntSize(src_type);
                int dst_size = irGetIntSize(dst_type);
                if (src_size > dst_size) {
                    op = IR_TRUNC;
                } else if (src_size < dst_size) {
                    if (ast->operand && ast->operand->type && ast->operand->type->issigned) {
                        op = IR_SEXT;
                    } else {
                        op = IR_ZEXT;
                    }
                } else {
                    op = IR_BITCAST;
                }
            } else if (irIsFloat(src_type) && irIsFloat(dst_type)) {
                if (ast->operand->type->size < ast->type->size) {
                    op = IR_FPEXT;
                } else if (ast->operand->type->size > ast->type->size) {
                    op = IR_FPTRUNC;
                } else {
                    op = IR_BITCAST;
                }
            } else if (irIsFloat(src_type) && irIsInt(dst_type)) {
                op = ast->type->issigned ? IR_FPTOSI : IR_FPTOUI;
            } else if (irIsInt(src_type) && irIsFloat(dst_type)) {
                if (ast->operand && ast->operand->type && ast->operand->type->issigned) {
                    op = IR_SITOFP;
                } else {
                    op = IR_UITOFP;
                }
            } else if (irIsPtr(src_type) && irIsInt(dst_type)) {
                op = IR_PTRTOINT;
            } else if (irIsInt(src_type) && irIsPtr(dst_type)) {
                op = IR_INTTOPTR;
            } else if (irIsPtr(src_type) && irIsPtr(dst_type)) {
                op = IR_BITCAST;
            } else {
                loggerWarning("IR lowering: unsupported cast %s -> %s, using bitcast\n",
                        irValueTypeToString(src_type),
                        irValueTypeToString(dst_type));
                op = IR_BITCAST;
            }

            IrInstr *cast_instr = irInstrNew(op, result, operand, NULL);
            irBlockAddInstr(ctx, cast_instr);
            return result;
        }

        case AST_CLASS_REF: {
            IrValue *field_addr = irExprAddress(ctx, ast);
            if (!field_addr) {
                loggerPanic("Class reference lowering failed: %s\n", astToString(ast));
            }
            IrValueType field_type = irConvertType(ast->type);
            if (irIsStruct(field_type) || field_type == IR_TYPE_ARRAY) {
                return field_addr;
            }
            IrValue *result = irTmp(field_type, ast->type->size);
            IrInstr *load = irLoad(result, field_addr);
            irBlockAddInstr(ctx, load);
            return result;
        }

        case AST_DEFAULT_PARAM: {
            if (ast->declvar) {
                return irExpr(ctx, ast->declvar);
            }
            if (ast->declinit) {
                return irExpr(ctx, ast->declinit);
            }
            return irConstInt(IR_TYPE_I64, 0);
        }

        case AST_GOTO:
        case AST_LABEL:
        case AST_FUNC:
        case AST_DECL:
        case AST_IF:
        case AST_FOR:
        case AST_WHILE:
        case AST_COMPOUND_STMT:
        case AST_ASM_STMT:
        case AST_ASM_FUNC_BIND:
        case AST_BREAK:
        case AST_CONTINUE:
        case AST_VAR_ARGS:
        case AST_ASM_FUNCDEF:
        case AST_FUN_PROTO:
        case AST_CASE:
        case AST_JUMP:
        case AST_EXTERN_FUNC:
        case AST_DO_WHILE:
        case AST_PLACEHOLDER:
        case AST_SWITCH:
        case AST_DEFAULT:
        case AST_SIZEOF:
        case AST_COMMENT:
        case AST_ARRAY_INIT:
            loggerWarning("IR lowering: array initializer expression fallback to 0\n");
            return irConstInt(IR_TYPE_I64, 0);
        default:
            loggerPanic("Expr Unhandled AST kind: %s\n", astKindToString(ast->kind));
    }
}

void irLowerAst(IrCtx *ctx, Ast *ast) {
    if (!ast) return;

    switch (ast->kind) {
        case AST_COMPOUND_STMT: {
            listForEach(ast->stms) {
                Ast *next = (Ast *)it->value;
                irLowerAst(ctx, next);
            }
            break;
        }
 
        case AST_BINOP:
        case AST_LVAR:
            (void)irExpr(ctx, ast);
            break;

        case AST_DECL: {
            Ast *var = ast->declvar;
            Ast *init = ast->declinit;
            IrInstr *ir_alloca = irAlloca(var->type);
            irAddStackSpace(ctx, var->type->size);
            irBlockAddInstr(ctx, ir_alloca);
            IrValue *local = ir_alloca->dst;
            u32 var_key = irAstVarKey(ast->declvar);
            if (var_key == 0) {
                loggerPanic("Unable to map local declaration kind `%s`\n",
                        astKindToString(ast->declvar->kind));
            }
            irFnAddVar(ctx->cur_func, var_key, local);

            if (init) {
                IrValue *ir_init = NULL;

                switch (init->kind) {
                    case AST_ARRAY_INIT: {
                        loggerWarning("IR lowering: array initializer for local `%s` is not fully implemented\n",
                                astLValueToString(var, 0));
                        break;
                    }

                    case AST_FUN_PROTO:
                    case AST_FUNC:
                    case AST_EXTERN_FUNC:
                    case AST_ASM_FUNCDEF:
                    case AST_ASM_FUNC_BIND: {
                        loggerPanic("Unhandled: %s\n", astKindToString(init->kind));
                        break;
                    }

                    case AST_ASM_FUNCALL:
                    case AST_FUNPTR_CALL:
                    case AST_FUNCALL: {
                        IrValue *ret = irFnCall(ctx, init);
                        IrInstr *ir_store = irStore(local, ret);
                        irBlockAddInstr(ctx, ir_store);
                        break;
                    }

                    case AST_UNOP: {
                        ir_init = irExpr(ctx, init);
                        IrInstr *ir_store = irStore(local, ir_init);
                        irBlockAddInstr(ctx, ir_store);
                        break;
                    }

                    default: {
                        ir_init = irExpr(ctx, init);
                        IrInstr *ir_store = irStore(local, ir_init);
                        irBlockAddInstr(ctx, ir_store);
                        break;
                    }    
                }
            }
            break;
        }

        case AST_FUNCALL:
        case AST_FUNPTR_CALL:
            irExpr(ctx, ast);
            break;

        case AST_RETURN: {
            if (ast->retval) {
                IrValue *ir_ret = irExpr(ctx, ast->retval);
                IrInstr *ir_store = irStore(ctx->cur_func->return_value, ir_ret);
                irBlockAddInstr(ctx, ir_store);
            }
            irJump(ctx->cur_func, ctx->cur_block, ctx->cur_func->exit_block);
            break;
        }

        case AST_IF: {
            IrValue *cond = irExpr(ctx, ast->cond);
            IrBlock *then_block = irBlockNew();
            IrBlock *end_block = irBlockNew();
            IrBlock *else_block = ast->els ? irBlockNew() : end_block;

            irBranch(ctx->cur_func, ctx->cur_block, cond, then_block, else_block);
            irFnAddBlock(ctx->cur_func, then_block);
            ctx->cur_block = then_block;
            irLowerAst(ctx, ast->then);
            irJump(ctx->cur_func, ctx->cur_block, end_block);

            if (ast->els) {
                irFnAddBlock(ctx->cur_func, else_block);
                ctx->cur_block = else_block;
                irLowerAst(ctx, ast->els);
                irJump(ctx->cur_func, ctx->cur_block, end_block);
            }

            irFnAddBlock(ctx->cur_func, end_block);
            ctx->cur_block = end_block;
            break;
        }

        case AST_FOR: {
            IrBlock *cond_block = irBlockNew();
            IrBlock *body_block = irBlockNew();
            IrBlock *step_block = irBlockNew();
            IrBlock *end_block = irBlockNew();

            if (ast->forinit) {
                irLowerAst(ctx, ast->forinit);
            }

            irJump(ctx->cur_func, ctx->cur_block, cond_block);
            irFnAddBlock(ctx->cur_func, cond_block);
            ctx->cur_block = cond_block;

            if (ast->forcond) {
                IrValue *cond = irExpr(ctx, ast->forcond);
                irBranch(ctx->cur_func, ctx->cur_block, cond, body_block, end_block);
            } else {
                irJump(ctx->cur_func, ctx->cur_block, body_block);
            }

            irFnAddBlock(ctx->cur_func, body_block);
            ctx->cur_block = body_block;
            irPushBreakTarget(ctx, end_block);
            irPushContinueTarget(ctx, step_block);
            irLowerAst(ctx, ast->forbody);
            irPopContinueTarget(ctx);
            irPopBreakTarget(ctx);
            irJump(ctx->cur_func, ctx->cur_block, step_block);

            irFnAddBlock(ctx->cur_func, step_block);
            ctx->cur_block = step_block;
            if (ast->forstep) {
                irLowerAst(ctx, ast->forstep);
            }
            irJump(ctx->cur_func, ctx->cur_block, cond_block);

            irFnAddBlock(ctx->cur_func, end_block);
            ctx->cur_block = end_block;
            break;
        }

        case AST_WHILE: {
            IrBlock *cond_block = irBlockNew();
            IrBlock *body_block = irBlockNew();
            IrBlock *end_block = irBlockNew();

            irJump(ctx->cur_func, ctx->cur_block, cond_block);
            irFnAddBlock(ctx->cur_func, cond_block);
            ctx->cur_block = cond_block;

            IrValue *cond = irExpr(ctx, ast->whilecond);
            irBranch(ctx->cur_func, ctx->cur_block, cond, body_block, end_block);

            irFnAddBlock(ctx->cur_func, body_block);
            ctx->cur_block = body_block;
            irPushBreakTarget(ctx, end_block);
            irPushContinueTarget(ctx, cond_block);
            irLowerAst(ctx, ast->whilebody);
            irPopContinueTarget(ctx);
            irPopBreakTarget(ctx);
            irJump(ctx->cur_func, ctx->cur_block, cond_block);

            irFnAddBlock(ctx->cur_func, end_block);
            ctx->cur_block = end_block;
            break;
        }

        case AST_DO_WHILE: {
            IrBlock *body_block = irBlockNew();
            IrBlock *cond_block = irBlockNew();
            IrBlock *end_block = irBlockNew();

            irJump(ctx->cur_func, ctx->cur_block, body_block);

            irFnAddBlock(ctx->cur_func, body_block);
            ctx->cur_block = body_block;
            irPushBreakTarget(ctx, end_block);
            irPushContinueTarget(ctx, cond_block);
            irLowerAst(ctx, ast->whilebody);
            irPopContinueTarget(ctx);
            irPopBreakTarget(ctx);
            irJump(ctx->cur_func, ctx->cur_block, cond_block);

            irFnAddBlock(ctx->cur_func, cond_block);
            ctx->cur_block = cond_block;
            IrValue *cond = irExpr(ctx, ast->whilecond);
            irBranch(ctx->cur_func, ctx->cur_block, cond, body_block, end_block);

            irFnAddBlock(ctx->cur_func, end_block);
            ctx->cur_block = end_block;
            break;
        }

        case AST_SWITCH: {
            IrValue *switch_value = irExpr(ctx, ast->switch_cond);
            IrBlock *end_block = irBlockNew();
            IrBlock *default_block = ast->case_default ? irBlockNew() : end_block;
            IrBlock *cmp_block = ctx->cur_block;
            irPushBreakTarget(ctx, end_block);

            for (u64 i = 0; i < ast->cases->size; ++i) {
                Ast *case_ast = vecGet(Ast *, ast->cases, i);
                IrBlock *case_block = irBlockNew();
                IrBlock *next_cmp = irBlockNew();

                ctx->cur_block = cmp_block;
                IrValue *cmp_result = NULL;
                if (case_ast->case_begin == case_ast->case_end) {
                    cmp_result = irTmp(IR_TYPE_I8, 1);
                    IrInstr *cmp = irInstrNew(IR_ICMP, cmp_result, switch_value,
                            irConstInt(switch_value->type, case_ast->case_begin));
                    cmp->extra.cmp_kind = IR_CMP_EQ;
                    irBlockAddInstr(ctx, cmp);
                } else {
                    IrValue *cmp_ge = irTmp(IR_TYPE_I8, 1);
                    IrValue *cmp_le = irTmp(IR_TYPE_I8, 1);
                    IrInstr *ge = irInstrNew(IR_ICMP, cmp_ge, switch_value,
                            irConstInt(switch_value->type, case_ast->case_begin));
                    ge->extra.cmp_kind = IR_CMP_GE;
                    irBlockAddInstr(ctx, ge);
                    IrInstr *le = irInstrNew(IR_ICMP, cmp_le, switch_value,
                            irConstInt(switch_value->type, case_ast->case_end));
                    le->extra.cmp_kind = IR_CMP_LE;
                    irBlockAddInstr(ctx, le);
                    cmp_result = irTmp(IR_TYPE_I8, 1);
                    irBlockAddInstr(ctx, irInstrNew(IR_AND, cmp_result, cmp_ge, cmp_le));
                }
                irBranch(ctx->cur_func, ctx->cur_block, cmp_result, case_block, next_cmp);

                irFnAddBlock(ctx->cur_func, case_block);
                ctx->cur_block = case_block;
                listForEach(case_ast->case_asts) {
                    Ast *stmt = it->value;
                    if (stmt->kind == AST_BREAK) {
                        irJump(ctx->cur_func, ctx->cur_block, end_block);
                        continue;
                    }
                    irLowerAst(ctx, stmt);
                }
                irJump(ctx->cur_func, ctx->cur_block, end_block);

                irFnAddBlock(ctx->cur_func, next_cmp);
                cmp_block = next_cmp;
            }

            ctx->cur_block = cmp_block;
            irJump(ctx->cur_func, ctx->cur_block, default_block);

            if (ast->case_default) {
                irFnAddBlock(ctx->cur_func, default_block);
                ctx->cur_block = default_block;
                listForEach(ast->case_default->case_asts) {
                    Ast *stmt = it->value;
                    if (stmt->kind == AST_BREAK) {
                        irJump(ctx->cur_func, ctx->cur_block, end_block);
                        continue;
                    }
                    irLowerAst(ctx, stmt);
                }
                irJump(ctx->cur_func, ctx->cur_block, end_block);
            }

            irFnAddBlock(ctx->cur_func, end_block);
            ctx->cur_block = end_block;
            irPopBreakTarget(ctx);
            break;
        }

        case AST_LITERAL:
        case AST_STRING:
        case AST_CAST:
        case AST_UNOP:
        case AST_ASM_FUNCALL:
        case AST_DEFAULT_PARAM:
            (void)irExpr(ctx, ast);
            break;

        case AST_GOTO:
        case AST_JUMP: {
            AoStr *label = astHackedGetLabel(ast);
            IrBlock *target = irGetOrCreateLabelBlock(ctx, label);
            if (!ctx->cur_block->sealed) {
                irJump(ctx->cur_func, ctx->cur_block, target);
            }
            /* Continue lowering into a fresh block for any subsequent
             * statements in this lexical scope. */
            IrBlock *next = irBlockNew();
            irFnAddBlock(ctx->cur_func, next);
            ctx->cur_block = next;
            break;
        }

        case AST_LABEL: {
            AoStr *label = astHackedGetLabel(ast);
            IrBlock *target = irGetOrCreateLabelBlock(ctx, label);
            if (ctx->cur_block != target) {
                if (!ctx->cur_block->sealed) {
                    irJump(ctx->cur_func, ctx->cur_block, target);
                }
                ctx->cur_block = target;
            }
            break;
        }

        case AST_GVAR:
        case AST_FUNC:
        case AST_ARRAY_INIT:
            /* No IR emitted here in the current backend. */
            break;

        case AST_BREAK: {
            IrBlock *target = irCurrentBreakTarget(ctx);
            if (!target) {
                target = ctx->cur_func->exit_block;
            }
            irJump(ctx->cur_func, ctx->cur_block, target);
            IrBlock *next = irBlockNew();
            irFnAddBlock(ctx->cur_func, next);
            ctx->cur_block = next;
            break;
        }
        case AST_CONTINUE: {
            IrBlock *target = irCurrentContinueTarget(ctx);
            if (!target) {
                target = ctx->cur_func->exit_block;
            }
            irJump(ctx->cur_func, ctx->cur_block, target);
            IrBlock *next = irBlockNew();
            irFnAddBlock(ctx->cur_func, next);
            ctx->cur_block = next;
            break;
        }
        case AST_CLASS_REF:
        case AST_ASM_STMT:
        case AST_ASM_FUNC_BIND:
        case AST_FUNPTR:
            irJump(ctx->cur_func, ctx->cur_block, ctx->cur_func->exit_block);
            break;
        case AST_VAR_ARGS:
        case AST_ASM_FUNCDEF:
        case AST_FUN_PROTO:
        case AST_CASE:
        case AST_EXTERN_FUNC:
        case AST_PLACEHOLDER:
        case AST_DEFAULT:
        case AST_SIZEOF:
        case AST_COMMENT:
            loggerPanic("Unhandled Ast kind `%s`\n%s\n",
                    astKindToString(ast->kind),
                    astToString(ast));
            break;
    }
}

void irSimplifyFunction(IrFunction *fn) {
    Set *work_queue_ids = setNew(16, &set_uint_type);
    List *queue = listNew();
    Set *blocks_to_delete = setNew(16, &set_int_type);

    (void)work_queue_ids;
    (void)queue;
    (void)blocks_to_delete;

    /* Any blocks that don't have a successor lets assume they jump to 
     * the return */
    listForEach(fn->blocks) {
        IrBlock *block = it->value;
        if (irBlockIsStartOrEnd(fn, block)) continue;
        Map *cur_successors = irBlockGetSuccessors(fn, block);
        if (cur_successors && cur_successors->size == 0) {
            /* @TODO
             * Think I need a new file to contain making ir instructions/ values*/
            irJump(fn, block, fn->exit_block);
        }
    }
}

void irMakeFunction(IrCtx *ctx, Ast *ast_func) {
    IrFunction *func = irFunctionNew(ast_func->fname);
    IrBlock *entry = irBlockNew();
    func->has_var_args = ast_func->has_var_args;
    listClear(ctx->break_targets, NULL);
    listClear(ctx->continue_targets, NULL);

    ctx->cur_block = entry;
    func->entry_block = entry;
    ctx->cur_func = func;
    ctx->label_blocks = mapNew(16, &map_cstring_opaque_type);

    irFnAddBlock(ctx->cur_func, entry);

    Ast *ast_var_args = NULL;
    for (u64 i = 0; i < ast_func->params->size; ++i) {
        Ast *ast_param = vecGet(Ast *,ast_func->params,i);

        if (ast_param->kind == AST_VAR_ARGS) {
            assert(func->has_var_args);
            ast_var_args = ast_param;
            break;
        }

        u32 key = irAstVarKey(ast_param);
        if (key == 0) {
            loggerPanic("Unhandled key kind: %s\n",
                    astKindToString(ast_param->kind));
        }

        IrValue *ir_tmp_var = irTmp(irConvertType(ast_param->type),
                                    ast_param->type->size);
        ir_tmp_var->kind = IR_VAL_PARAM;
        irFnAddVar(func, key, ir_tmp_var);
        vecPush(func->params, ir_tmp_var);
        irAddStackSpace(ctx, ast_param->type->size);
    }

    if (ast_var_args) {
        IrValue *argc = irTmp(irConvertType(ast_var_args->argc->type),
                              ast_var_args->argc->type->size);
        argc->kind = IR_VAL_PARAM;
        irFnAddVar(func, ast_var_args->argc->lvar_id, argc);
        vecPush(func->params, argc);
        irAddStackSpace(ctx, ast_var_args->argc->type->size);

        IrValue *argv = irTmp(IR_TYPE_PTR, 8);
        argv->kind = IR_VAL_PARAM;
        irFnAddVar(func, ast_var_args->argv->lvar_id, argv);
        vecPush(func->params, argv);
        irAddStackSpace(ctx, 8);
    }

    IrBlock *exit_block = irBlockNew();
    IrInstr *ir_return_space = irAlloca(ast_func->type->rettype);
    irAddStackSpace(ctx, ast_func->type->rettype->size);
    IrValue *ir_return_var = ir_return_space->dst;
    func->return_value = ir_return_var;
    IrBlockMapping *ir_exit_block_mapping = irBlockMappingNew(exit_block->id);
    mapAddIntOrErr(func->cfg, ir_exit_block_mapping->id, ir_exit_block_mapping);

    func->exit_block = exit_block;
    irFnAddBlock(ctx->cur_func, exit_block);

    irLowerAst(ctx, ast_func->body);
    irSimplifyFunction(func);
    mapRelease(ctx->label_blocks);
    ctx->label_blocks = NULL;
    listClear(ctx->break_targets, NULL);
    listClear(ctx->continue_targets, NULL);
}

void irDump(Cctrl *cc) {
    IrCtx *ctx = irCtxNew(cc);
    listForEach(cc->ast_list) {
        Ast *ast = (Ast *)it->value;
        if (ast->kind == AST_FUNC) {
            ctx->cur_func = NULL;
            irMakeFunction(ctx, ast);
            irPrintFunction(ctx->cur_func);
        }
    }
}

IrCtx *irLowerProgram(Cctrl *cc) {
    IrCtx *ctx = irCtxNew(cc);
    listForEach(cc->ast_list) {
        Ast *ast = (Ast *)it->value;
        if (ast->kind == AST_FUNC) {
            ctx->cur_func = NULL;
            irMakeFunction(ctx, ast);
            irCtxAddFunction(ctx, ctx->cur_func);
        } else if (ast->kind == AST_DECL && ast->declvar && ast->declvar->kind == AST_GVAR) {
            irCollectGlobal(ctx, ast->declvar, ast->declinit);
        } else if (ast->kind == AST_GVAR) {
            irCollectGlobal(ctx, ast, NULL);
        }
    }
    return ctx;
}

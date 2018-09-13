/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
* @author Abhishek VB
* @date June 22 2015
*/


#ifndef DISARM_H
#define DISARM_H

#include <capstone/capstone.h>

static csh handle;

struct platform {
  cs_arch arch;
  cs_mode mode;
  unsigned char *code;
  size_t size;
  char *comment;
  int syntax;
};

static void print_string_hex(FILE *log_fd, char *comment, unsigned char *str, size_t len)
{
  unsigned char *c;

  fprintf(log_fd,"%s", comment);
  for (c = str; c < str + len; c++) {
    fprintf(log_fd,"0x%02x ", *c & 0xff);
  }

  fprintf(log_fd,"\n");
}

static void print_insn_detail(FILE* log_fd, cs_insn *ins)
{
  cs_arm *arm;
  int i;

  // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
  if (ins->detail == NULL)
    return;

  arm = &(ins->detail->arm);

  if (arm->op_count)
    fprintf(log_fd,"\top_count: %u\n", arm->op_count);

  for (i = 0; i < arm->op_count; i++) {
    cs_arm_op *op = &(arm->operands[i]);
    switch((int)op->type) {
      default:
      break;
      case ARM_OP_REG:
      fprintf(log_fd,"\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
      break;
      case ARM_OP_IMM:
      fprintf(log_fd,"\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
      break;
      case ARM_OP_FP:
      fprintf(log_fd,"\t\toperands[%u].type: FP = %f\n", i, op->fp);
      break;
      case ARM_OP_MEM:
      fprintf(log_fd,"\t\toperands[%u].type: MEM\n", i);
      if (op->mem.base != X86_REG_INVALID)
        fprintf(log_fd,"\t\t\toperands[%u].mem.base: REG = %s\n",
          i, cs_reg_name(handle, op->mem.base));
      if (op->mem.index != X86_REG_INVALID)
        fprintf(log_fd,"\t\t\toperands[%u].mem.index: REG = %s\n",
          i, cs_reg_name(handle, op->mem.index));
      if (op->mem.scale != 1)
        fprintf(log_fd,"\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
      if (op->mem.disp != 0)
        fprintf(log_fd,"\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

      break;
      case ARM_OP_PIMM:
      fprintf(log_fd,"\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
      break;
      case ARM_OP_CIMM:
      fprintf(log_fd,"\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
      break;
      case ARM_OP_SETEND:
      fprintf(log_fd,"\t\toperands[%u].type: SETEND = %s\n", i, op->setend == ARM_SETEND_BE? "be" : "le");
      break;
      case ARM_OP_SYSREG:
      fprintf(log_fd,"\t\toperands[%u].type: SYSREG = %u\n", i, op->reg);
      break;
    }

    if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
      if (op->shift.type < ARM_SFT_ASR_REG)
        // shift with constant value
        fprintf(log_fd,"\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
      else
        // shift with register
        fprintf(log_fd,"\t\t\tShift: %u = %s\n", op->shift.type,
          cs_reg_name(handle, op->shift.value));
    }

    if (op->vector_index != -1) {
      fprintf(log_fd,"\t\toperands[%u].vector_index = %u\n", i, op->vector_index);
    }

    if (op->subtracted)
      fprintf(log_fd,"\t\tSubtracted: True\n");
  }

  if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID)
    fprintf(log_fd,"\tCode condition: %u\n", arm->cc);

  if (arm->update_flags)
    fprintf(log_fd,"\tUpdate-flags: True\n");

  if (arm->writeback)
    fprintf(log_fd,"\tWrite-back: True\n");

  if (arm->cps_mode)
    fprintf(log_fd,"\tCPSI-mode: %u\n", arm->cps_mode);

  if (arm->cps_flag)
    fprintf(log_fd,"\tCPSI-flag: %u\n", arm->cps_flag);

  if (arm->vector_data)
    fprintf(log_fd,"\tVector-data: %u\n", arm->vector_data);

  if (arm->vector_size)
    fprintf(log_fd,"\tVector-size: %u\n", arm->vector_size);

  if (arm->usermode)
    fprintf(log_fd,"\tUser-mode: True\n");

  if (arm->mem_barrier)
    fprintf(log_fd,"\tMemory-barrier: %u\n", arm->mem_barrier);

  fprintf(log_fd,"\n");
}

#endif

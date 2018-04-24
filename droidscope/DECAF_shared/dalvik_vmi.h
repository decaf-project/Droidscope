/*
    Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

    DECAF is based on QEMU, a whole-system emulator. You can redistribute
    and modify it under the terms of the GNU GPL, version 3 or later,
    but it is made available WITHOUT ANY WARRANTY. See the top-level
    README file for more details.

    For more information about DECAF and other softwares, see our
    web site at:
    http://sycurelab.ecs.syr.edu/

    If you have any questions about DECAF,please post it on
    http://code.google.com/p/decaf-platform/


 * dalvik_vmi.h
 *
 *  Created on: September 14, 2015
 *      Author: Abhishek V B
 */


#ifndef DALVIK_VMI_H
#define DALVIK_VMI_H


#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

void dalvik_vmi_init(void);

void load_dalvik_ops(void);

void disas_dalvik_ins(CPUArchState *env, const uint16_t *ins, target_ulong dalvik_file_base, char *output);

bool address_is_opcode(target_ulong address);

#ifdef __cplusplus
}
#endif

#endif //DALVIK_VMI_H
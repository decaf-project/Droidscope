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
 *  Created on: November 9th, 2015
 *      Author: Abhishek V B
 */


#ifndef ART_VMI_H
#define ART_VMI_H


#ifdef __cplusplus
#include <string>
#include <unordered_map>
#include <unordered_set>
//Art
extern std::unordered_map<target_ulong, void*> base_to_oat_file;
extern std::unordered_map < target_ulong,
    std::unordered_map<uint32_t, void *>> base_to_dex_files;
extern std::unordered_map<target_ulong,
                          std::unordered_map<target_ulong, std::string>>
    base_to_offsets;

extern std::unordered_map<target_ulong,
                          std::unordered_map<target_ulong, target_ulong>>
base_to_sizes;


extern std::unordered_map<target_ulong, std::string>
    framework_offsets;

extern std::unordered_map<target_ulong, target_ulong>
    framework_sizes;

extern bool framework_offsets_extracted;
//end

extern "C" {
#endif


#include <inttypes.h>

void art_vmi_init(void);

void load_from_oat(void);

void clear_oat_dumpers();

void extract_oat_file(CPUArchState *env, target_ulong module_base, char **output_file);


int art_vmi_method_at(uint32_t base, uint32_t offset, char *method_name);

const char* art_method_at_index(uint32_t method_idx);

#ifdef __cplusplus
}
#endif

#endif //ART_VMI_H

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
*/
/*
* dalvik_vmi.cpp
*
*  Created on: September 15, 2015
* 	Author : Abhishek V B
*/

#include <inttypes.h>
#include <string>
#include <list>
#include <set>
#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unordered_map>
#include <unordered_set>

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <queue>
#include <sys/time.h>
#include <math.h>
#include <mcheck.h>
#include <stddef.h>
#include <fstream>
#include <cstdio>

extern "C" {
//#include "qemu-common.h"
#include "config.h"
#include "hw/hw.h" // AWH

}  // extern "C"


	
#include "DECAF_shared/DECAF_main.h"
#include "DECAF_shared/vmi.h"
#include "DECAF_shared/vmi_callback.h"
#include "DECAF_shared/linux_vmi_.h"
#include "DECAF_shared/linux_procinfo.h"
#include "DECAF_shared/utils/SimpleCallback.h"
#include "DECAF_shared/DECAF_callback.h"
#include "DECAF_shared/vmi_c_wrapper.h"
#include "DECAF_shared/function_map.h"

#include "DECAF_shared/dalvik_callback.h"
#include "DECAF_shared/dalvik_common.h"
#include "DECAF_shared/dalvik_vmi.h"

/* Dalvik headers */
#include "dalvik/vm/oo/Object.h"
#include "dalvik/libdex/InstrUtils.h"
#include "dalvik/vm/interp/InterpState.h"
#include "DECAF_shared/elfio/elfio.hpp"
#include <elfio/elfio_dump.hpp>
#include "DECAF_shared/DECAF_fileio.h"



extern void dumpOneInstruction(uint32_t base,const u2 * insns, char *output);

extern bool isExtractRequired(uint32_t base);

extern bool parseDexAndAdd(uint32_t base, const char *file_name);

#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)

using namespace std;
using namespace ELFIO;


#define BREAK_IF(x) if(x) break

//Global variable used to read values from the stack

/* PLEASE ORGANIZE THESE VARS! */
static int monitored __attribute__((unused)) = 0;
static DECAF_Handle method_begin_cb_handle = DECAF_NULL_HANDLE;
static target_ulong libdvm_call_method_addr = 0x00, dvmMterpStdRunAddr, dvmMterpStdBailAddr;
static target_ulong set_target_cr3  __attribute__((unused)) = 0x00;
static process *system_server_process   __attribute__((unused)) = NULL;
static SimpleCallback_t Dalvik_VMI_callbacks[DS_LAST_CB];
static unordered_set<target_ulong> dalvik_op_bases;

static string temp_dir_name;
static bool dalvik_method_cb_activated = false, dalvik_insn_cb_activated = false;
static bool dalvik_ops_translating  __attribute__((unused)) = false;

static char dir_name[] = "/tmp/XXXXXX";

/* ------------------------ */


bool address_is_opcode(target_ulong address)
{
	return dalvik_op_bases.count(address);
}

	
void dalvik_vmi_init()
{
	mkdtemp(dir_name);
	temp_dir_name = dir_name;
	monitor_printf(default_mon, "Dalvik initda!~\n");
}

void load_dalvik_ops(void)
{
	//here we know that the system_server process started and
	//now we grab the libdvm.so and extract op addresses from it
	process *pe = VMI_find_process_by_comm_name("zygote");
	int total_ops = 0;
	target_ulong dvmAsmInstructionStartAddr, dvmAsmInstructionEndAddr;
	dvmAsmInstructionStartAddr =
	funcmap_get_pc("libdvm.so","dvmAsmInstructionStart", pe->cr3);
	dvmAsmInstructionEndAddr =
	funcmap_get_pc("libdvm.so","dvmAsmInstructionEnd", pe->cr3);
	
	libdvm_call_method_addr
	= funcmap_get_pc("libdvm.so","dvmInterpret(Thread*, Method const*, JValue*)", pe->cr3);
	
	dvmMterpStdRunAddr =
	funcmap_get_pc("libdvm.so","dvmMterpStdRun", pe->cr3);
	
	dvmMterpStdBailAddr =
	funcmap_get_pc("libdvm.so","dvmMterpStdBail", pe->cr3);
	
	
	while(dvmAsmInstructionStartAddr < dvmAsmInstructionEndAddr)
	{
		++total_ops;
		dalvik_op_bases.insert(dvmAsmInstructionStartAddr);
		dvmAsmInstructionStartAddr += 0x40;
	}
	
	monitor_printf(default_mon, "Read %d Davik Ops\n", total_ops);
}


/* Call back action for file_walk
*/
static TSK_WALK_RET_ENUM
write_action(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
	if (size == 0)
		return TSK_WALK_CONT;
	
	std::string *sp = static_cast<std::string*>(ptr);
	
	sp->append(buf,size);
	
	return TSK_WALK_CONT;
}



void disas_dalvik_ins(CPUArchState *env, const uint16_t *ins, target_ulong dalvik_file_base, char *output)
{
	if(output != NULL)
		output[0] = '\0';
	
	if(isExtractRequired(dalvik_file_base)) {
		module *odex_module = VMI_find_module_by_base(DECAF_getPGD(env),dalvik_file_base);

		if(!odex_module)
			return;
		
		TSK_FS_FILE *file_fs = tsk_fs_file_open_meta(disk_info_internal[0].fs, NULL, (TSK_INUM_T)odex_module->inode_number);
		
		void *file_stream = static_cast<void*>(new std::string());
		std::string *local_copy = static_cast<std::string*>(file_stream);
		
		int ret __attribute__((unused)) = 0;
		ret = tsk_fs_file_walk(file_fs, TSK_FS_FILE_WALK_FLAG_NONE, write_action, file_stream);
		
   		size_t file_size = (size_t) (local_copy->length());
		string file_name = temp_dir_name+ string("/") + odex_module->name; 

		FILE *fd_tmp = fopen(file_name.c_str(), "w+");
        fwrite(local_copy->c_str(), 1, file_size, fd_tmp);
        fclose(fd_tmp);
		
		if(!parseDexAndAdd(dalvik_file_base, file_name.c_str()))
		{
			monitor_printf(default_mon, "Problem with opening dex/odex file, please check. File name %s, Module Base 0x%08x, Module inode %d.\n", odex_module->name, dalvik_file_base, odex_module->inode_number);
			return;
		}
		dumpOneInstruction(dalvik_file_base, ins, output);

		//unlink(file_name.c_str());
		
	}
	else
	{
		dumpOneInstruction(dalvik_file_base, ins, output);
 	}
}

//static void insn_begin_cb(DECAF_Callback_Params* params)
static void bb_begin_cb(DECAF_Callback_Params* params)
{
	target_ulong curr_pc = params->bb.cur_pc;
	CPUArchState *env = params->bb.env;
	target_ulong cr3 = DECAF_getPGD(env);
	
	if(dalvik_method_cb_activated)
	{
		if(curr_pc != libdvm_call_method_addr)
		 	goto next_check;
		
		Dalvik_VMI_Callback_Params params__;
		params__.mb.env = env;
		
		//Read the second arguement off of a(1)
		target_ulong method_ptr = env->regs[1];
		
		target_ulong method_name_ptr, method_name_offset = method_ptr + offsetof(struct Method, name);
		DECAF_read_mem_with_pgd(env, pgd_strip(cr3), method_name_offset, &method_name_ptr, sizeof(target_ulong));
		DECAF_read_mem_with_pgd(env, pgd_strip(cr3), method_name_ptr, params__.mb.method_name, METHOD_NAME_MAX);
		params__.mb.method_name[METHOD_NAME_MAX - 1] = '\0';
		
		
		target_ulong source_path_ptr, class_ptr, source_path_offset; //, method_name_offset = method_ptr + offsetof(struct Method, name);
		DECAF_read_mem_with_pgd(env, pgd_strip(cr3), method_ptr, &class_ptr, sizeof(target_ulong));
		source_path_offset = class_ptr + offsetof(struct ClassObject,sourceFile);
		DECAF_read_mem_with_pgd(env, pgd_strip(cr3), source_path_offset, &source_path_ptr, sizeof(target_ulong));
		DECAF_read_mem_with_pgd(env, pgd_strip(cr3), source_path_ptr, params__.mb.dalvik_file_name, METHOD_NAME_MAX);
		params__.mb.dalvik_file_name[METHOD_NAME_MAX - 1] = '\0';
		
		target_ulong dvm_dex_ptr, dvm_dex_offset, mem_map_offset;
		struct MemMapping *extracted_map;
		char mem_map_buffer[sizeof(struct MemMapping)];
		dvm_dex_offset = class_ptr + offsetof(struct ClassObject, pDvmDex);
		DECAF_read_mem_with_pgd(env, pgd_strip(cr3), dvm_dex_offset, &dvm_dex_ptr, sizeof(target_ulong));
		mem_map_offset = dvm_dex_ptr + offsetof(struct DvmDex, memMap);
		DECAF_read_mem_with_pgd(env, pgd_strip(cr3), mem_map_offset, mem_map_buffer, sizeof(struct MemMapping));
		extracted_map = reinterpret_cast<struct MemMapping *>(mem_map_buffer);
		
		params__.mb.file_base = reinterpret_cast<target_ulong>(extracted_map->baseAddr);
		
		SimpleCallback_dispatch(&Dalvik_VMI_callbacks[DALVIK_METHOD_BEGIN_CB], &params__);
	}
	
next_check:
	
	if(dalvik_insn_cb_activated)
	{
		if(dalvik_op_bases.count(curr_pc))
		{
			/* We do not have the struct thread definition to keep things simple,
			* but we have the definition of InterpSaveState, which sits as the first member of
			* the thread struct, so we just use that.
			*/
			Dalvik_VMI_Callback_Params params__;
			params__.ib.env = env;
			
			struct MemMapping *extracted_map;
			char mem_map_buffer[sizeof(struct MemMapping)];
			target_ulong mem_map_offset, dvm_dex_ptr, dvm_dex_offset, interp_state_ptr = getDalvikSELF(env);
			dvm_dex_offset = interp_state_ptr + offsetof(struct InterpSaveState, methodClassDex);
			DECAF_read_mem_with_pgd(env, pgd_strip(cr3), dvm_dex_offset, &dvm_dex_ptr, sizeof(target_ulong));
			mem_map_offset = dvm_dex_ptr + offsetof(struct DvmDex, memMap);
			DECAF_read_mem_with_pgd(env, pgd_strip(cr3), mem_map_offset, mem_map_buffer, sizeof(struct MemMapping));
			extracted_map = reinterpret_cast<struct MemMapping *>(mem_map_buffer);
			params__.ib.dalvik_file_base = reinterpret_cast<target_ulong>(extracted_map->baseAddr);

			target_ulong curr_insn, dalvik_pc = getDalvikPC(env);
			DECAF_read_mem_with_pgd(env, pgd_strip(cr3), dalvik_pc, &curr_insn, sizeof(target_ulong));
			params__.ib.insn = (uint32_t) curr_insn;
			params__.ib.dalvik_pc = dalvik_pc;
			//params__.ib.insn = (uint32_t) getDalvikINST(env);
			SimpleCallback_dispatch(&Dalvik_VMI_callbacks[DALVIK_INSN_BEGIN_CB], &params__);
			//disas_dalvik_ins(env, (u2 *)&insn, params__.ib.dalvik_file_base);
			
		}
	}
	
}

DECAF_Handle Dalvik_VMI_register_callback(Dalvik_callback_type_t cb_type, Dalvik_VMI_callback_func_t cb_func, int *cb_cond)
{
	
	switch(cb_type)
	{
		case DALVIK_METHOD_BEGIN_CB :
			if(method_begin_cb_handle == DECAF_NULL_HANDLE)
			{
				method_begin_cb_handle
					= DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, bb_begin_cb, NULL);
				//= DECAF_register_callback(DECAF_INSN_BEGIN_CB, &insn_begin_cb,NULL);
			}
		
			dalvik_method_cb_activated = true;
			return (SimpleCallback_register(&Dalvik_VMI_callbacks[cb_type], (SimpleCallback_func_t)cb_func, cb_cond));
		
		case DALVIK_INSN_BEGIN_CB :		
			if(method_begin_cb_handle == DECAF_NULL_HANDLE)
			{
				method_begin_cb_handle
					= DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, bb_begin_cb, NULL);

			}
			dalvik_insn_cb_activated = true;
			return (SimpleCallback_register(&Dalvik_VMI_callbacks[cb_type], (SimpleCallback_func_t)cb_func, cb_cond));
		
		default:
			monitor_printf(default_mon, "Wrong callback type input for this call\n");
			return DECAF_NULL_HANDLE;
	}
	return DECAF_NULL_HANDLE;
}

int Dalvik_VMI_unregister_callback(VMI_callback_type_t cb_type, DECAF_Handle handle)
{
	switch(cb_type)
	{
		case DALVIK_METHOD_BEGIN_CB:
		if(dalvik_insn_cb_activated == false && method_begin_cb_handle != DECAF_NULL_HANDLE) {
			DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, method_begin_cb_handle);
			method_begin_cb_handle = DECAF_NULL_HANDLE;
		}
		
		SimpleCallback_unregister(&Dalvik_VMI_callbacks[cb_type], handle);
		dalvik_method_cb_activated = false;
		return 0;
		
		case DALVIK_INSN_BEGIN_CB:
		dalvik_insn_cb_activated = false;
		if(dalvik_method_cb_activated == false && method_begin_cb_handle != DECAF_NULL_HANDLE) {
			DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, method_begin_cb_handle);
			method_begin_cb_handle = DECAF_NULL_HANDLE;
		}
		SimpleCallback_unregister(&Dalvik_VMI_callbacks[cb_type], handle);
		return 0;
		
		default:
		return -1;
	}
	
	return -1;
}



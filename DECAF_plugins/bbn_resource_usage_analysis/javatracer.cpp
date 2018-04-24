
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
* @author Abhishek Vasisht Bhaskar
* @date March 15, 2016
* Basic plugin which records function calls and their lengths using Droidscope.
*/

#include <sys/time.h>

#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_shared/vmi_callback.h"
#include "vmi_c_wrapper.h"
#include "DECAF_shared/dalvik_common.h"
#include "function_map.h"
#include "vmi.h"
#include "art_vmi.h"
#include <iostream>
#include <fstream>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <set>
#include <sstream> 
#include <fstream>


#define SIZEOF_TYPE(struct_type) (sizeof(struct_type))
#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)


//Unsed but maybe used in future vars
static int __attribute__((unused)) monitoring = 1;
static uint32_t __attribute__((unused)) counter = 0;
static tmodinfo_t __attribute__((unused)) module_info;
//end

#define LOGW 0

#define DECAF_printf(...) monitor_printf(default_mon, __VA_ARGS__)

static plugin_interface_t hookapitests_interface;
//static DECAF_Handle modulebegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle insn_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle memwrite_handle = DECAF_NULL_HANDLE;
static DECAF_Handle module_load_handle = DECAF_NULL_HANDLE, block_begin_cb_handle = DECAF_NULL_HANDLE;
//static DECAF_Handle dalvik_insn_cb_handle = DECAF_NULL_HANDLE;

static unordered_set<std::string> oat_files_extracted;

/* Data structure to hold callstack data */
struct tiny {
	public:
	std::string function_name;
	uint32_t instructions;
	uint32_t memory;
	target_ulong lr;

	tiny(std::string name_) : function_name(name_)
	{
		instructions = 0;
		memory = 0;
		lr = 0;
	}
};
/* Shadow java callstack */
std::vector <tiny *> call_stack;

static std::map<std::string,std::string> funcToModuleMapping;

extern void DECAF_output_init(Monitor* mon);

static char targetname[512];
static char actualname[512];

static uint32_t fucntion_insns = 0;
static target_ulong current_lr = 0x00, base, targetpid = 0;
//static target_ulong current_pc = 0, current_cr3 = 0;
static target_ulong targetcr3 = 0;
static unordered_set<target_ulong> targetcr3s;
static bool inside_function = false;

static std::string output_dir = "./DECAF_plugins/bbn_resource_usage_analysis/out/";
static FILE * pFile_java_function_cpu;
static FILE * pFile_java_function_memory;
static FILE * pFile_java_function_thirdPartyLibs;


// static void handle_instruction((Dalvik_VMI_Callback_Params* params)
// {
// 	CPUState *env = params->ib.env;
// 	target_ulong here_cr3 = DECAF_getPGD(env);
// 	if(here_cr3 != targetcr3) 
// 		return;
// 	disas_dalvik_ins(env, (uint16_t *)&(params->ib.insn), params->ib.dalvik_file_base);
// }


static void insn_cb(DECAF_Callback_Params *param)
{
	CPUArchState *env = param->bb.env;

	target_ulong cur_pc = param->bb.cur_pc;
	target_ulong cr3 = DECAF_getPGD(env);
  
	if(DECAF_is_in_kernel(env) || !(targetcr3s.count(cr3))) {
		return;
	}

	/* Check if we're out of the function */
	if(inside_function)
	{
		if(cur_pc == call_stack.back()->lr) 
		{/* Dump data, mark outside_funciton - false */
			tiny* to_dump = call_stack.back();
			call_stack.pop_back();

			// make the instruction count inclusive
			if(!call_stack.empty())
			{
				tiny* next = call_stack.back();
				next->instructions += to_dump->instructions;
			}

			std::string funcName = to_dump->function_name;
      
      		// we exclude all the functions in framework
      		std::string modName = funcToModuleMapping.find(funcName)->second;
			//if(strstr(modName.c_str(), "framework") == NULL) {
				fprintf(pFile_java_function_cpu, "%s instruction count: %d\n",  funcName.c_str(), to_dump->instructions);
				fprintf(pFile_java_function_memory, "%s memory consumption: %d\n", funcName.c_str(), to_dump->memory);
			//}


			current_lr = fucntion_insns = 0;
			delete to_dump;

			if(call_stack.empty())
				inside_function = false;
		}
		else
		{
			++(call_stack.back()->instructions);
		}
	}
}

 /* Block begin callback
 * This is where we check if the PC corresponds to an offset in an OAT file, 
 * hence classifying it as a JAVA function
 *
 * Before that, for each OAT file that we get, we use APIs from libart-dscopeartdump.so to extract
 * offsets from the OAT file and store them
 */

static void block_begin_cb(DECAF_Callback_Params *param) 
{
	char modname[512];
	char functionname[512];
	
	CPUArchState *env = param->bb.env;

	target_ulong cur_pc = param->bb.cur_pc;
	target_ulong cr3 = DECAF_getPGD(env);
	  
	if(DECAF_is_in_kernel(env) || !(targetcr3s.count(cr3))) {
		return;
	}

	module* art_module = NULL;
  	art_module = VMI_find_module_by_pc(cur_pc, cr3, &base);


	//if(module != NULL && module->is_oat)// && strncmp(module->name, "system@", 7) != 0)
	if (art_module != NULL 
          && (strstr(art_module->name, "oat") != NULL || strstr(art_module->name, "dex") != NULL || strstr(art_module->name, "dalvik") != NULL)
          && strstr(art_module->name, "framework") == NULL)
	{
		char art_method[1024];
		if(oat_files_extracted.find(art_module->name) == oat_files_extracted.end())
	    {
	    	char* oat_file_str;
			extract_oat_file(env, base, &oat_file_str);
			oat_files_extracted.insert(art_module->name);
	    }

	    if(art_vmi_method_at(art_module->inode_number, (cur_pc - base), art_method))
	    {
			current_lr = env->regs[14];
			inside_function = true;
			tiny *to_insert = new tiny(std::string(art_method));
			to_insert->lr = current_lr;

			//std::pair<std::map<std::string, std::string>::iterator,bool> ret =
			funcToModuleMapping.insert(std::pair<std::string, std::string>(std::string(art_method), std::string(art_module->name)));

			// std::string func = std::string(art_method) + " module - " + std::string(module->name);
			// fprintf(pFile_java_function_memory, "[FUNCTION CALL] %s\n", func.c_str());

			call_stack.push_back(to_insert);
	    }
	}

	if(art_module != NULL && (strstr(art_module->name, "libc") != NULL))
	{
		if(funcmap_get_name_c(cur_pc, DECAF_getPGD(env), modname, functionname) == 0)
		{
			if(strstr(functionname, "operator new") != 0)
			{
				 if(!call_stack.empty())
				 {
				 	for(size_t i = 0; i < call_stack.size(); i++)
				 		call_stack[i]->memory += env->regs[0];
				 }
			}
		}
	}
}

static void register_hooks()
{
	insn_begin_handle = DECAF_register_callback(DECAF_INSN_BEGIN_CB, insn_cb, NULL);
	block_begin_cb_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb, NULL);
	//dalvik_insn_cb_handle = Dalvik_VMI_register_callback(DALVIK_INSN_BEGIN_CB, handle_instruction, NULL);
}

static void createproc_callback(VMI_Callback_Params* params)
{
	if (targetpid == 0 && strlen(targetname) > 1 && strstr(params->cp.name, targetname) != 0) 
	{
		targetpid = params->cp.pid;
		targetcr3 = params->cp.cr3;
		targetcr3s.insert(targetcr3);

		strncpy(actualname, params->cp.name, strlen(params->cp.name));
		actualname[511] = '\0';

		register_hooks();
		DECAF_printf("process found: pid=%08x, cr3=%08x, name = %s\n", targetpid, targetcr3, params->cp.name);
	}
	else if (targetpid != 0 && params->cp.parent_pid == targetpid) 
	{
    	targetcr3s.insert(params->cp.cr3);
    	DECAF_printf("child process found: pid=%08x, cr3=%08x, name = %s\n", params->cp.pid, params->cp.cr3, params->cp.name);
	}
}

static void do_hookapitests(Monitor* mon, const char* proc_name)
{
	if(strlen(proc_name) < 512) {
		strncpy(targetname, proc_name, strlen(proc_name));
		targetname[strlen(proc_name)+1] = '\0';

		std::string log_name_cpu = output_dir + "analysisResult_cpu.log";
		pFile_java_function_cpu = fopen(log_name_cpu.c_str(), "w");

		std::string log_name_memory = output_dir + "analysisResult_memory.log";
		pFile_java_function_memory = fopen(log_name_memory.c_str(), "w");

		std::string log_name_thirdPartyLibs = output_dir + "analysisResult_thirdPartyLibs.log";
		pFile_java_function_thirdPartyLibs = fopen(log_name_thirdPartyLibs.c_str(), "w");

		if(pFile_java_function_cpu == NULL 
			|| pFile_java_function_memory == NULL 
			|| pFile_java_function_thirdPartyLibs == NULL)
		{
			DECAF_printf("ERROR OPENNING LOG FILES. EXIT");
			exit(0);
		}
	}
	else
		return;
}

static void do_clear_log(Monitor *mon, char *command)
{

}

static int hookapitests_init(void)
{
	//DECAF_output_init(NULL);
	targetname[0] = '\0';
  
	//register for process create and process remove events
	processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &createproc_callback, NULL);
  
	return (0);
}

static void hookapitests_cleanup(void)
{
	if (processbegin_handle != DECAF_NULL_HANDLE) 
	{
		VMI_unregister_callback(VMI_CREATEPROC_CB,
 		processbegin_handle);
		processbegin_handle = DECAF_NULL_HANDLE;
	}

	if (module_load_handle != DECAF_NULL_HANDLE) 
	{
		VMI_unregister_callback(VMI_LOADMODULE_CB, module_load_handle);
		module_load_handle = DECAF_NULL_HANDLE;
	}

	if(block_begin_cb_handle != DECAF_NULL_HANDLE)
	{
		DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb_handle);
	}

	if(insn_begin_handle != DECAF_NULL_HANDLE)
	{
		DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, insn_begin_handle);
	}  

	if(memwrite_handle != DECAF_NULL_HANDLE)
	{
		DECAF_unregister_callback(DECAF_MEM_WRITE_CB, memwrite_handle);
	}

	if(pFile_java_function_cpu != NULL)
		fclose(pFile_java_function_cpu);
	if(pFile_java_function_memory != NULL)
		fclose(pFile_java_function_memory);
	if(pFile_java_function_thirdPartyLibs != NULL)
		fclose(pFile_java_function_thirdPartyLibs);
}

static mon_cmd_t hookapitests_term_cmds[] = {
	#include "plugin_cmds.h"
	{ NULL, NULL, }, 
};

extern "C" plugin_interface_t* init_plugin(void) {
	hookapitests_interface.mon_cmds = hookapitests_term_cmds;
	hookapitests_interface.plugin_cleanup = &hookapitests_cleanup;
	//initialize the plugin
	hookapitests_init();
	return (&hookapitests_interface);
}

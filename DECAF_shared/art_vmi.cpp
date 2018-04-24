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
*  Created on: November 9, 2015
*   Author : Abhishek V B
*            abhsakar@syr.edu
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
#include <pthread.h>    /* POSIX Threads */

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


#include "DECAF_shared/art_vmi.h"


#include "DECAF_shared/elfio/elfio.hpp"
#include <elfio/elfio_dump.hpp>
#include "DECAF_shared/DECAF_fileio.h"

// TODO: PLEASE FIND A BETTER WAY TO DO THIS!!
//#include "../droidscope_oatdump/myoatdump.h"
#include "../include/monitor/monitor.h"
#include "vmi.h"


using namespace std;
using namespace ELFIO;


#define BREAK_IF(x) if(x) break

#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)

static char dir_name[] = "/tmp/XXXXXX";
static string temp_dir_name;
static unordered_set<target_ulong> oat_files_extracted;

//void extract_oat_file(CPUArchState *env, target_ulong module_base, std::string& output_file);



/* ------------------------ */

/* This is stuff I have to remove */
static target_ulong targetcr3 = 0;
static tmodinfo_t module_info;
static bool in_oat = true;
static char actualname[512];
static char targetname[512];
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static target_ulong targetpid = -1;
static DECAF_Handle modulebegin_handle = DECAF_NULL_HANDLE;

//Art
std::unordered_map<target_ulong, void *> base_to_oat_file;
std::unordered_map < target_ulong, std::unordered_map<uint32_t, void *>> base_to_dex_files;
std::unordered_map<target_ulong, std::unordered_map<target_ulong, std::string>> base_to_offsets;

std::unordered_map<target_ulong, std::string> framework_offsets;

std::unordered_map<target_ulong, target_ulong> framework_sizes;

std::unordered_map<target_ulong, std::unordered_map<target_ulong, target_ulong>> base_to_sizes;



bool framework_offsets_extracted = false;
//end

static void hook_all(DECAF_Callback_Params* param)
{
   
}

static void register_hooks()
{
    modulebegin_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, hook_all, NULL);
}

static void createproc_callback(VMI_Callback_Params* params)
{
	//monitor_printf(default_mon, "Process started with name = %s\n", params->cp.name);
    if (strlen(targetname) > 1 && strstr(params->cp.name, targetname) != 0) {
        targetpid = params->cp.pid;
        targetcr3 = params->cp.cr3;
        
        strncpy(actualname, params->cp.name, strlen(params->cp.name));
        actualname[511] = '\0';
        
        register_hooks();
        monitor_printf(default_mon, "Process found: pid=%08x, cr3=%08x, name = %s\n", targetpid, targetcr3, params->cp.name);
    }
}


/* end */

void art_vmi_init()
{
    mkdtemp(dir_name);
    temp_dir_name = dir_name;
    monitor_printf(default_mon, "ART Runtime VMI Init!\n");
    
    //THIS IS THE OTHER STUFF
    //processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB,
    //&createproc_callback, NULL);
    
    strcpy(targetname, "tester");
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


//Extract ART method symbols for one module,
// We assume that only one process is being tracked now.
void extract_oat_file(CPUArchState *env, target_ulong module_base, char **output_file)
{
    //pthread_t oatdump_thread;
	module* oat_module = VMI_find_module_by_base(DECAF_getPGD(env),module_base);

    if(!oat_module) { 
		monitor_printf(default_mon, "Error opening module with base \n");
    	return;
    }
    
    TSK_FS_FILE *file_fs = tsk_fs_file_open_meta(disk_info_internal[DATA_PARTITION].fs, NULL, (TSK_INUM_T)oat_module->inode_number);
    
    void *file_stream = static_cast<void*>(new std::string());
    std::string *local_copy = static_cast<std::string*>(file_stream);
    
    
    int ret __attribute__((unused)) = 0;
    ret = tsk_fs_file_walk(file_fs, TSK_FS_FILE_WALK_FLAG_NONE, write_action, file_stream);
    
    size_t file_size = (size_t) (local_copy->length());
    string file_name = temp_dir_name + string("/") + oat_module->name;
    
    FILE *fd_tmp = fopen(file_name.c_str(), "w+");
    
    fwrite(local_copy->c_str(), 1, file_size, fd_tmp);
    fclose(fd_tmp);

	//monitor_printf(default_mon, "file_name %s opened \n", file_name.c_str());

	*output_file = (char *)malloc(sizeof(char) * file_name.size());
	
    strncpy(*output_file, file_name.c_str(), file_name.size());
	
	try
	{
	  //entry_main(oat_module->inode_number, file_name.c_str());
	}
	catch(...) // <<- catch all
	{
	  return ;
	}
	
}

int art_vmi_method_at(uint32_t base, uint32_t offset, char *method_name)
{
	//return art_method_at(base, offset, method_name);
}

const char* art_method_at_index(uint32_t method_idx)
{
	//return NULL;
	//return art_method_name(method_idx);
}









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
/********************************************************************
** function_map.cpp
** Author: Heng Yin <heyin@syr.edu>
**
**
** used to map eip to function name.  this file uses the fact
** that TEMU knows module information for loaded modules.
** using this, and the print_funcs_on command, we can print
** every library call that is made within the program.
**
*/

#include <inttypes.h>
#include <map>
#include <vector>
#include <list>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cassert>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <utility>

#include "vmi_c_wrapper.h"
#include "DECAF_main.h"
#include "DECAF_vm_compress.h"
#include "hw/hw.h" // AWH
#include "DECAF_shared/vmi.h"
#include "function_map.h"
//#include "DECAF_shared/hookapi.h"

using namespace std;

// map ``module name" -> "function name" -> offset
map<string, map<string, target_ulong> > map_function_offset;

// map "module name" -> "offset" -> "function name"
map<string, map<uint64_t, string> > map_offset_function;

static char* alloc_copy(const char *source)
{
        char *dest = NULL;
        if(source)
        {
                dest = new char[strlen(source)];//(char *) malloc(strlen(source));
                strcpy(dest,source);
        }
        return dest;
}

int VMI_list_symbols(Monitor *mon, char *module_name, int pid, int base)
{
  string mod_name(module_name);
  char key[256];
  process *proc = VMI_find_process_by_pid((target_ulong) pid);

  if(!proc)
  {
    monitor_printf(mon, "Process not found!\n");
    return -1;
  }

  
  module *mod = VMI_find_module_by_base(proc->cr3, (target_ulong)base);
  
  if(!mod)
  {
    monitor_printf(mon, "Module %s not found!\n", module_name);
    return -1;
  }

  
  /* AVB: For Linux, we do not extract exported symbols regularly when the modules are discovered
   * Instead we just extract the `inode number' belonging to the module and do the extraction
   * when there is a request for a mapping from pc-->function_name or function_name-->pc.
   * This function does symbol extraction of the module specified in `mod' if not already done
   * 
   * For Windows though, this function just returns.
   */
  VMI_extract_symbols(mod,base);
  
  sprintf(key, "%u_%s", mod->inode_number, module_name);
  
  if(!map_offset_function.count(key))
  {
    monitor_printf(mon, "Module's symbols not extracted!\n", module_name);
    return -1;
  }

  monitor_printf(mon, "module - %s\n", module_name);

  map<  uint64_t, string>::iterator iter;
    for (iter = map_offset_function[key].begin(); iter != map_offset_function[key].end(); iter++)
    {
    monitor_printf(mon, "function - %s offset - %08x \n",  iter->second.c_str(), iter->first);
    }
}

target_ulong funcmap_get_pc(const char *module_name, const char *function_name, target_ulong cr3) __attribute__((optimize("O0")));
target_ulong funcmap_get_pc(const char *module_name, const char *function_name, target_ulong cr3)
{
  target_ulong base;
  module *mod = VMI_find_module_by_name(module_name, cr3, &base);
  if(!mod)
    return 0;


  /* AVB: For Linux, we do not extract exported symbols regularly when the modules are discovered
   * Instead we just extract the `inode number' belonging to the module and do the extraction
   * when there is a request for a mapping from pc-->function_name or function_name-->pc.
   * This function does symbol extraction of the module specified in `mod' if not already done
   * 
   * For Windows though, this function just returns.
   */
  VMI_extract_symbols(mod,base);

  char key[256];
  sprintf(key, "%u_%s", mod->inode_number, mod->name);

  
  map<string, map<string, target_ulong> >::iterator iter = map_function_offset.find(key);
  if(iter == map_function_offset.end())
    return 0;

  map<string, target_ulong>::iterator iter2 = iter->second.find(function_name);
  if(iter2 == iter->second.end())
    return 0;

  return iter2->second + base;
}

int funcmap_get_name(target_ulong pc, target_ulong cr3, string &mod_name, string &func_name)
{
  target_ulong base;


  module *mod = VMI_find_module_by_pc(pc, cr3, &base);
  if(!mod)
    return -1;

  /* AVB: For Linux, we do not extract exported symbols regularly when the modules are discovered
   * Instead we just extract the `inode number' belonging to the module and do the extraction
   * when there is a request for a mapping from pc-->function_name or function_name-->pc.
   * This function does symbol extraction of the module specified in `mod' if not already done
   * 
   * For Windows though, this function just returns.
   */
  VMI_extract_symbols(mod,base);

  char key[256];
  sprintf(key, "%u_%s", mod->inode_number, mod->name);
  
  map<string, map<uint64_t, string> >::iterator iter = map_offset_function.find(key);
  if (iter == map_offset_function.end())
    return -1;

  map<uint64_t, string>::iterator iter2 = iter->second.find(pc - base);
  if (iter2 == iter->second.end())
    return -1;

  mod_name = mod->name;
  func_name = iter2->second;
  //std::cout << iter2->second << "\n";
  return 0;
}

int funcmap_get_name_c(target_ulong pc, target_ulong cr3, char *mod_name, char *func_name)
{
  string mod, func;
  int ret = funcmap_get_name(pc, cr3, mod, func);
  if(ret == 0) {
    //we assume the caller has allocated enough space for mod_name and func_name
    strncpy(mod_name, mod.c_str(), 512);
    strncpy(func_name, func.c_str(), 512);
  }

  return ret;
}

//


#define BOUNDED_STR(len) "%" #len "s"
#define BOUNDED_QUOTED(len) "%" #len "[^\"]"
#define BOUNDED_STR_x(len) BOUNDED_STR(len)
#define BOUNDED_QUOTED_x(len) BOUNDED_QUOTED(len)
#define BSTR BOUNDED_STR_x(511)
#define BQUOT BOUNDED_QUOTED_x(511)


void parse_function(const char *message)
{
}
// void funcmap_insert_function(const char *module, const char *fname, uint32_t offset) __attribute__((optimize("O0")));
void funcmap_insert_function(const char *module,const string &fname, target_ulong offset, target_ulong inode_number)
{
  // cout << module << fname << offset << endl;
  // char *offsetchar = alloc_copy(fname);
  
  char key[256];
  sprintf(key, "%u_%s", inode_number, module);

  if(fname.find('$') != string::npos)
  	return;

  
  map<string, map<uint64_t, string> >::iterator iter2 = map_offset_function.find(key);
  if (iter2 == map_offset_function.end()) {
    map<uint64_t, string> offset_func;
    offset_func.insert(pair<uint64_t, string>(offset, fname));
    map_offset_function[key] = offset_func;
  } else {
  	if(iter2->second.count(offset) == 0) {
	    iter2->second.insert(pair<uint64_t, string>(offset, fname));
  	    //std::cout << "offset "<< offset << "function " << fname << " +++ " <<  map_offset_function[key].find(offset)->second << "\n";
  	}
  }

  
  map<string, map<string, target_ulong> >::iterator iter = map_function_offset.find(key);
  if (iter == map_function_offset.end()) {
    map<string, target_ulong> func_offset;
    func_offset[fname] = offset;
    map_function_offset[key] = func_offset;
  } else {
    iter->second.insert(pair<string, target_ulong>(fname, offset));
  }



}

static void function_map_save(QEMUFile * f, void *opaque)
{

}

static int function_map_load(QEMUFile * f, void *opaque, int version_id)
{

}


void function_map_init()
{

}

void function_map_cleanup()
{
  map_function_offset.clear();
  map_offset_function.clear();
  
  //unregister_savevm(NULL, "funmap", 0);
}


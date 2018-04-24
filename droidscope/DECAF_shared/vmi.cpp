#include <inttypes.h>
#include <string>
#include <list>
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
//#include <glib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH


#ifdef __cplusplus
};
#endif /* __cplusplus */



//AVB - introduced slowly
#include "linux_readelf.h"
//#include "hookapi.h"
//#include "shared/hookapi.h"
#include "function_map.h"

#include "DECAF_shared/vmi_callback.h"
#include "DECAF_shared/vmi.h"
#include "DECAF_shared/DECAF_main.h"
#include "DECAF_shared/utils/SimpleCallback.h"
#include "DECAF_shared/linux_vmi_.h"
#include "DECAF_shared/DECAF_callback.h"

using namespace std;
//using namespace std::tr1;


//map cr3 to process_info_t
unordered_map < target_ulong, process * >process_map;
//map pid to process_info_t
unordered_map < target_ulong, process * >process_pid_map;
// module list
unordered_map < string, module * >module_name;

target_ulong GuestOS_index_c = 11;
uintptr_t insn_handle_c = 0;

target_ulong VMI_guest_kernel_base = 0;

static void block_end_cb(DECAF_Callback_Params* temp)
{
    static long long count_out = 0x8000000000L;	// detection fails after 1000 basic blocks
    int found_guest_os = 0;


    // We know it can only be linux
    if(find_linux(temp->ie.env, insn_handle_c) == 1)
    {
        found_guest_os = 1;
    }

    if(found_guest_os)
    {
        DECAF_unregister_callback(DECAF_TLB_EXEC_CB, insn_handle_c);
        linux_vmi_init();
    }

}


process* VMI_find_process_by_name(const char *name)
{
	process *proc;
	unordered_map<uint32_t, process *>::iterator iter;
	
	for (iter = process_map.begin(); iter != process_map.end(); iter++) {

		proc = iter->second;
		
		if(strstr(proc->name,name) != NULL)
			return proc;
	}

	return 0;
	
}

module * VMI_find_next_module(target_ulong pc, target_ulong pgd, target_ulong *base, target_ulong *prev_base)
{
    process *proc ;
    CPUState *here_env = reinterpret_cast<CPUState *>(mon_get_cpu_external(default_mon));

    proc = VMI_find_process_by_pgd(pgd);
    if(!proc) return NULL;

    if(!proc->modules_extracted)
        traverse_mmap((CPUArchState *)(here_env->env_ptr), proc);

    unordered_map< target_ulong, module * >::iterator iter, next_iter;
    for (iter = proc->module_list.begin(); iter != proc->module_list.end(); iter++)
    {
        next_iter = std::next(iter, 1);
        module *mod = iter->second;

        if ((pc < next_iter->first) && (pc > (mod->size + iter->first)))
        {
            *base = next_iter->first;
            *prev_base = mod->size + iter->first;
            return mod;
        }
    }
	
    return NULL;
}

process* VMI_find_process_by_comm_name(const char *name)
{
	process *proc;
    unordered_map < target_ulong, process * >::iterator iter;
    for (iter = process_map.begin(); iter != process_map.end(); iter++)
    {
        proc = iter->second;
        if (strstr((const char *)name,proc->comm_name) != NULL)
        {
            return proc;
        }
    }
    return 0;
}


process * VMI_find_process_by_pgd(target_ulong pgd)
{
    unordered_map < target_ulong, process * >::iterator iter =
        process_map.find(pgd);

    if (iter != process_map.end())
        return iter->second;

    return NULL;
}


process *VMI_find_process_by_pid(target_ulong pid)
{
    unordered_map < target_ulong, process * >::iterator iter =
        process_pid_map.find(pid);

    if (iter == process_pid_map.end())
        return NULL;

    return iter->second;
}


module* VMI_find_module_by_key(const char *key)
{

    string temp(key);
    unordered_map < string, module * >::iterator iter =
        module_name.find(temp);
    if (iter != module_name.end())
    {
        return iter->second;
    }
    return NULL;
}

module* VMI_find_module_by_name_slow(const char *name) 
{
	string to_check(name);

	unordered_map< string, module * >::iterator iter;
	for (iter = module_name.begin(); iter != module_name.end(); iter++)
	{
		module *mod = iter->second;
		if (iter->first.find(name) != std::string::npos)
		{
			return mod;
		}
	}
	return NULL;

}

module * VMI_find_module_by_base(target_ulong pgd, target_ulong base)
{
    unordered_map<target_ulong, process *>::iterator iter = process_map.find(pgd);
    process *proc;
	CPUState *here_env = reinterpret_cast<CPUState *>(mon_get_cpu_external(default_mon));
	
    if (iter == process_map.end()) //pid not found
        return NULL;

    proc = iter->second;	

	if(!proc->modules_extracted)
		traverse_mmap((CPUArchState *)(here_env->env_ptr), proc);

    unordered_map<target_ulong, module *>::iterator iter_m = proc->module_list.find(base);
    if(iter_m == proc->module_list.end())
        return NULL;

    return iter_m->second;
}

module * VMI_find_module_by_pc(target_ulong pc, target_ulong pgd, target_ulong *base)
{
    process *proc ;
	CPUState *here_env = reinterpret_cast<CPUState *>(mon_get_cpu_external(default_mon));
		/*
    if (pc >= VMI_guest_kernel_base)
    {
        proc = process_pid_map[0];
    }
    else
    {
        unordered_map < uint32_t, process * >::iterator iter_p = process_map.find(pgd);
        if (iter_p == process_map.end())
            return NULL;

        proc = iter_p->second;
    }
    */
		proc = VMI_find_process_by_pgd(pgd);
		if(!proc)
			return NULL;
		
    if(!proc->modules_extracted)
       	traverse_mmap((CPUArchState *)(here_env->env_ptr), proc);

    unordered_map< target_ulong, module * >::iterator iter;
    for (iter = proc->module_list.begin(); iter != proc->module_list.end(); iter++)
    {
        module *mod = iter->second;
        if ((pc > iter->first) && (pc < (mod->size + iter->first)))
        {
            *base = iter->first;
            return mod;
        }
    }

    return NULL;
}

module * VMI_find_module_by_name(const char *name, target_ulong pgd, target_ulong *base)
{
	CPUState *here_env = reinterpret_cast<CPUState *>(mon_get_cpu_external(default_mon));
    unordered_map < target_ulong, process * >::iterator iter_p = process_map.find(pgd);
    if (iter_p == process_map.end())
        return NULL;

    process *proc = iter_p->second;

    if(!proc->modules_extracted)
        traverse_mmap((CPUArchState *)(here_env->env_ptr), proc);

    unordered_map< target_ulong, module * >::iterator iter;
    for (iter = proc->module_list.begin(); iter != proc->module_list.end(); iter++)
    {
        module *mod = iter->second;
        if (strcasecmp(mod->name, name) == 0)
        {
            *base = iter->first;
            return mod;
        }
    }

    return NULL;
}

/*
 *
 * Add module to a global list. per process's module list only keeps pointers to this global list.
 *
 */
int VMI_add_module(module *mod, const char *key)
{
    if(mod==NULL)
        return -1;
    string temp(key);
    unordered_map < string, module * >::iterator iter = module_name.find(temp);
    if (iter != module_name.end())
    {
        return -1;
    }
    module_name[temp]=mod;
    return 1;
}
static SimpleCallback_t VMI_callbacks[VMI_LAST_CB];

DECAF_Handle VMI_register_callback(
    VMI_callback_type_t cb_type,
    VMI_callback_func_t cb_func,
    int *cb_cond
)
{
    if ((cb_type > VMI_LAST_CB) || (cb_type < 0))
    {
        return (DECAF_NULL_HANDLE);
    }

    return (SimpleCallback_register(&VMI_callbacks[cb_type], (SimpleCallback_func_t)cb_func, cb_cond));
}

int VMI_unregister_callback(VMI_callback_type_t cb_type, DECAF_Handle handle)
{
    if ((cb_type > VMI_LAST_CB) || (cb_type < 0))
    {
        return (DECAF_NULL_HANDLE);
    }

    return (SimpleCallback_unregister(&VMI_callbacks[cb_type], handle));
}

int VMI_is_MoudleExtract_Required()
{
    if(LIST_EMPTY(&VMI_callbacks[VMI_LOADMODULE_CB])&& LIST_EMPTY(&VMI_callbacks[VMI_REMOVEMODULE_CB]))
        return 0;

    return 1;
}

int VMI_create_process(process *proc, bool callback_also)
{
  	proc->modules_extracted = true;

		unordered_map < target_ulong, process * >::iterator iter =
        process_pid_map.find(proc->pid);
    if (iter != process_pid_map.end())
    {
        // Found an existing process with the same pid
        // We force to remove that one.
        //	monitor_printf(default_mon, "remove process pid %d", proc->pid);
        VMI_remove_process(proc->pid);
    }

    unordered_map < target_ulong, process * >::iterator iter2 =
        process_map.find(proc->cr3);
    if (iter2 != process_map.end())
    {
        // Found an existing process with the same CR3
        // We force to remove that process
        //	monitor_printf(default_mon, "removing due to cr3 0x%08x\n", proc->cr3);
        VMI_remove_process(iter2->second->pid);
    }

    process_pid_map[proc->pid] = proc;
    process_map[proc->cr3] = proc;

		if(callback_also) 
		{
			VMI_process_callback_only(proc);
		}

#if 0
    if(strlen(name))   //TEST ONLY!! -Heng
    {
        params.lmm.pid = pid;
        params.lmm.cr3 = cr3;
        params.lmm.name = name;
        SimpleCallback_dispatch(&procmod_callbacks[PROCMOD_LOADMAINMODULE_CB], &params);
    }
#endif
    return 0;
}

void VMI_process_callback_only(process * proc)
{
		VMI_Callback_Params params;
	  params.cp.cr3 = proc->cr3;
	  params.cp.pid = proc->pid;
	  params.cp.name = proc->name;
	  params.cp.short_name = proc->comm_name;
	  params.cp.parent_pid = proc->parent_pid;
	  SimpleCallback_dispatch(&VMI_callbacks[VMI_CREATEPROC_CB], &params);
}

int VMI_remove_process(target_ulong pid)
{
    VMI_Callback_Params params;
    process *proc;
    unordered_map < target_ulong, process * >::iterator iter =
        process_pid_map.find(pid);

    if(iter == process_pid_map.end())
        return -1;

    // params.rp.proc = iter->second;

    params.rp.cr3 = iter->second->cr3;
    params.rp.pid = iter->second->pid;
    params.rp.name = iter->second->name;
    // printf("removing %d %x %s\n", params.rp.pid, params.rp.cr3, params.rp.name);
    SimpleCallback_dispatch(&VMI_callbacks[VMI_REMOVEPROC_CB], &params);

    process_map.erase(iter->second->cr3);
    process_pid_map.erase(iter);
    delete iter->second;

    return 0;
}



int VMI_insert_module(target_ulong pid, target_ulong base, module *mod)
{
    VMI_Callback_Params params;
    params.lm.pid = pid;
    params.lm.base = base;
    params.lm.name = mod->name;
    params.lm.size = mod->size;
    params.lm.full_name = mod->fullname;
    unordered_map<target_ulong, process *>::iterator iter = process_pid_map.find(
                pid);
    process *proc;

    if (iter == process_pid_map.end()) //pid not found
        return -1;

    proc = iter->second;
    params.lm.cr3 = proc->cr3;

    //Now the pages within the module's memory region are all resolved
    //We also need to removed the previous modules if they happen to sit on the same region

    for (target_ulong vaddr = base; vaddr < base + mod->size; vaddr += 4096)
    {
        proc->resolved_pages.insert(vaddr >> 12);
        proc->unresolved_pages.erase(vaddr >> 12);
        //TODO: UnloadModule callback
        proc->module_list.erase(vaddr);
    }


    //Now we insert the new module in module_list
    proc->module_list[base] = mod;

    // AVB - need to ADD THIS BACK!!
    //check_unresolved_hooks();

    SimpleCallback_dispatch(&VMI_callbacks[VMI_LOADMODULE_CB], &params);

    return 0;
}

int VMI_remove_module(target_ulong pid, target_ulong base)
{
    VMI_Callback_Params params;
    params.rm.pid = pid;
    params.rm.base = base;
    unordered_map<target_ulong, process *>::iterator iter = process_pid_map.find(
                pid);
    process *proc;

    if (iter == process_pid_map.end()) //pid not found
        return -1;

    proc = iter->second;
    params.rm.cr3 = proc->cr3;

    unordered_map<target_ulong, module *>::iterator m_iter = proc->module_list.find(base);
    if(m_iter == proc->module_list.end())
        return -1;

    module *mod = m_iter->second;

    params.rm.name = mod->name;
    params.rm.size = mod->size;
    params.rm.full_name = mod->fullname;

    proc->module_list.erase(m_iter);

    SimpleCallback_dispatch(&VMI_callbacks[VMI_REMOVEMODULE_CB], &params);


    for (target_ulong vaddr = base; vaddr < base + mod->size; vaddr += 4096)
    {
        proc->resolved_pages.erase(vaddr >> 12);
        proc->unresolved_pages.erase(vaddr >> 12);
    }

    //proc->module_list.erase(m_iter);

    return 0;
}

int VMI_update_name(target_ulong pid, char *name)
{
    monitor_printf(default_mon,"updating name : not implemented\n");
}
int VMI_remove_all()
{
    monitor_printf(default_mon,"remove all not implemented\n");
}

int VMI_dipatch_lmm(process *proc)
{

    VMI_Callback_Params params;
    params.cp.cr3 = proc->cr3;
    params.cp.pid = proc->pid;
    params.cp.name = proc->name;

    SimpleCallback_dispatch(&VMI_callbacks[VMI_CREATEPROC_CB], &params);

    return 0;
}
int VMI_dispatch_lm(module * m, process *p, gva_t base)
{
    VMI_Callback_Params params;
    params.lm.pid = p->pid;
    params.lm.base = base;
    params.lm.name = m->name;
    params.lm.size = m->size;
    params.lm.full_name = m->fullname;
    params.lm.cr3 = p->cr3;
    SimpleCallback_dispatch(&VMI_callbacks[VMI_LOADMODULE_CB], &params);
}

void VMI_init()
{
    monitor_printf(default_mon, "\nVmi init! (DroidScope)\n");
    insn_handle_c = DECAF_register_callback(DECAF_TLB_EXEC_CB, block_end_cb, NULL);
}

//AVB
// This functions returns if the inode_number for this particular module is 0
// THis would be the case for windows modules
int VMI_extract_symbols(module *mod, target_ulong base)
{
    if(mod->inode_number == 0)
        return 0;
    if(!mod->symbols_extracted)
    {
        //AVB - ADD IT BACK!!
        read_elf_info(mod->name, base, mod->inode_number);
        mod->symbols_extracted = 1;
    }

    return 1;
}


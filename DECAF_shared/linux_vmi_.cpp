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
* linux_vmi_new.cpp
*
*  Created on: June 26, 2015
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
//#include <tr1/unordered_map>
//#include <tr1/unordered_set>
#include <unordered_map>
#include <unordered_set>

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <queue>
#include <sys/time.h>
#include <math.h>
//#include <glib.h>
#include <mcheck.h>
#ifdef __cplusplus
extern "C" {
    #endif /* __cplusplus */
    #include "cpu.h"
    #include "config.h"
    #include "hw/hw.h" // AWH
    //#include "qemu-timer.h"
    #ifdef __cplusplus
};
#endif /* __cplusplus */
    
#include "DECAF_shared/DECAF_main.h"
//#include "DECAF_target.h"
#include "DECAF_shared/vmi.h"
#include "DECAF_shared/linux_vmi_.h"
#include "DECAF_shared/linux_procinfo.h"
#include "DECAF_shared/utils/SimpleCallback.h"
#include "DECAF_shared/DECAF_callback.h"

#include "DECAF_shared/vmi_callback.h"
#include "DECAF_shared/vmi_c_wrapper.h"
#include "DECAF_shared/function_map.h"
#include "DECAF_shared/dalvik_vmi.h"

/* AVB - Will be introduced slowly
#include "linux_readelf.h"
#include "hookapi.h"

#include "linux_readelf.h"
*/

#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)


using namespace std;
//using namespace std::tr1;

#define BREAK_IF(x) if(x) break

//Global variable used to read values from the stack
int monitored = 0;

// current linux profile
static ProcInfo OFFSET_PROFILE = {"VMI"};
static bool first = true;

// Android process discovery related data structures.
unordered_set <target_ulong> cr3s_to_track;
static DECAF_Handle zygote_init_cb_handle = DECAF_NULL_HANDLE;
target_ulong zygote_init_addr = 0x00;

static bool hasEnding (std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}

static void zygote_init_callback(DECAF_Callback_Params* params)
{
    CPUArchState *env = params->bb.env;
    
    char second_name[VMI_MAX_PROCESS_NAME_FULL+1] __attribute__((unused));
    
    target_ulong target_cr3 = DECAF_getPGD(env);
    process *target_proc;
    
    string functionname;
    string modname;
    
    
    if(!cr3s_to_track.count(target_cr3))
    	return;

	//monitor_printf(default_mon, "here!\n");
    
    target_proc = VMI_find_process_by_pgd(target_cr3);
    
    target_ulong mm __attribute__((unused)) , mm_arg __attribute__((unused)), name_ptr;
    
    name_ptr = DECAF_getFirstParam(env);
    
    //DECAF_read_mem(env, target_proc->EPROC_base_addr + OFFSET_PROFILE.ts_mm, &mm, 4);
    //DECAF_read_mem(env, mm + OFFSET_PROFILE.mm_arg_start, &mm_arg, 4);
    //DECAF_read_mem_with_pgd(env, pgd_strip(target_cr3), mm_arg, target_proc->name, VMI_MAX_PROCESS_NAME_FULL);
    DECAF_read_mem_with_pgd(env, pgd_strip(target_cr3), name_ptr, target_proc->name, VMI_MAX_PROCESS_NAME_FULL);
    //monitor_printf(default_mon, "process %s, ... , %s\n", target_proc->name, second_name);
    VMI_process_callback_only(target_proc);
    cr3s_to_track.erase(target_cr3);
    
}



//  Traverse the task_struct linked list and add all un-added processes
//  This function is called
static void traverse_task_struct_add(CPUArchState *env)
{
    target_ulong task_pid = 0;
    const int MAX_LOOP_COUNT = 1024;	// prevent infinite loop
    target_ulong next_task, mm, proc_cr3, task_pgd, ts_parent_pid, ts_real_parent, mm_arg;
    next_task = OFFSET_PROFILE.init_task_addr;
    process* pe;
    
    for (int count = MAX_LOOP_COUNT; count > 0; --count)
    {
        
        BREAK_IF(DECAF_read_mem(env, next_task + (OFFSET_PROFILE.ts_tasks),
        &next_task, sizeof(target_ptr)) < 0);
        
        next_task -= OFFSET_PROFILE.ts_tasks;
        
        
        if(OFFSET_PROFILE.init_task_addr == next_task)
        {
            break;
        }
        
        BREAK_IF(DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_mm,
        &mm, 4) < 0);
        
        if (mm != 0)
        {
            BREAK_IF(DECAF_read_mem(env, mm + OFFSET_PROFILE.mm_pgd,
            &task_pgd, 4) < 0);
            
            proc_cr3 = DECAF_get_phys_addr(env, task_pgd);
        }
        else
        {
            // We don't add kernel processed for now.
            proc_cr3 = -1;
            continue;
        }
        
        
        if (!VMI_find_process_by_pgd(proc_cr3))
            //if (!VMI_find_process_by_pid(task_pid))
        {
            
            // get task_pid
            BREAK_IF(DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_tgid,
            &task_pid, 4) < 0);
            
            // get parent task's base address
            BREAK_IF(DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_real_parent,
            &ts_real_parent, 4) < 0
            ||
            DECAF_read_mem(env, ts_real_parent + OFFSET_PROFILE.ts_tgid,
            &ts_parent_pid, 4) < 0);
            
            BREAK_IF(DECAF_read_mem(env, mm + OFFSET_PROFILE.mm_arg_start, &mm_arg, 4) < 0);
            
            pe = new process();
            pe->pid = task_pid;
            pe->parent_pid = ts_parent_pid;
            pe->cr3 = proc_cr3;
            pe->EPROC_base_addr = next_task; // store current task_struct's base address
            pe->name[0] = '\0';
            pe->resolved = false;
            
            BREAK_IF(DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_comm,
            pe->comm_name, SIZEOF_COMM) < 0);
            
            DECAF_read_mem_with_pgd(env, pgd_strip(task_pgd), mm_arg, pe->name, VMI_MAX_PROCESS_NAME_FULL);
            
            if(strstr(pe->comm_name, "main") != NULL)
            {
                VMI_create_process(pe, false);
                pe->modules_extracted = false;
                if(zygote_init_cb_handle == DECAF_NULL_HANDLE)
                {
                    //load_dalvik_ops();
                    zygote_init_addr = funcmap_get_pc("libcutils.so","set_process_name", pe->cr3);
                    //zygote_init_cb_handle = DECAF_registerOptimizedBlockBeginCallback(&zygote_init_callback ,zygote_init_addr ,zygote_init_addr);
					zygote_init_cb_handle =       DECAF_registerOptimizedBlockBeginCallback(&zygote_init_callback, zygote_init_addr, OCB_CONST);
                }
                cr3s_to_track.insert(pe->cr3);
            }
            else
            {
                VMI_create_process(pe, true);
                pe->modules_extracted = false;
            }
            
            //monitor_printf(default_mon,"process %s started pid %u parent_pid %u \n", pe->name, pe->pid, ts_parent_pid);
            
        }
    }
}

// Traverse the task_struct linked list and updates the internal DECAF process data structures on process exit
// This is called when the linux system call `proc_exit_connector` is called.
static process *traverse_task_struct_remove(CPUArchState *env)
{
    set<target_ulong> pids;
    target_ulong task_pid = 0;
    process *right_proc = NULL;
    target_ulong right_pid = 0;
    
    const int MAX_LOOP_COUNT = 1024;
    
    target_ulong next_task, mm;
    next_task = OFFSET_PROFILE.init_task_addr;
    
    for (int count = MAX_LOOP_COUNT; count > 0; --count)
    {
        BREAK_IF(DECAF_read_mem(env, next_task + (OFFSET_PROFILE.ts_tasks),
        &next_task, 4) < 0);
        
        next_task -= OFFSET_PROFILE.ts_tasks;
        
        if(OFFSET_PROFILE.init_task_addr == next_task)
        {
            break;
        }
        
        BREAK_IF(DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_mm,
        &mm, 4) < 0);
        
        if (mm != 0)
        {
            DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_tgid,
            &task_pid, 4);
            // Collect PIDs of all processes in the task linked list
            pids.insert(task_pid);
        }
        
    }
    
    // Compare the collected list with the internal list. We track the Process which is removed and call `VMI_process_remove`
    for(unordered_map < target_ulong, process * >::iterator iter = process_pid_map.begin(); iter != process_pid_map.end(); ++iter)
    {
        if(!pids.count(iter->first))
        {
            right_pid = iter->first;
            right_proc = iter->second;
            break;
        }
    }
    
    //DEBUG-only
    // if(right_proc != NULL)
    //monitor_printf(default_mon,"process with pid [%08x] %s ended\n",right_pid,right_proc->name);
    
    VMI_remove_process(right_pid);
    return right_proc;
}

// Traverse the memory map for a process
void traverse_mmap(CPUArchState *env, void *opaque)
{
    process *proc = (process *)opaque;

    char *require_debug = NULL;
    //char *require_debug = strstr(proc->name, "printspooler");
    bool always_true = true;
	
    target_ulong mm, vma_curr, vma_file, f_dentry, f_inode, mm_mmap, vma_next = 0x00;// NULL
    set<target_ulong> module_bases;

	vector<target_ulong> vma_starts;
	vector<target_ulong> vma_ends;

    unsigned int inode_number;
    target_ulong vma_vm_start = 0, vma_vm_end = 0;
    target_ulong last_vm_start __attribute__((unused)) = 0, last_vm_end = 0, mod_vm_start = 0;
    char name[256];	// module file path
    string last_mod_name;
    module *mod = NULL;
    bool is_oat = false;
    
    if (DECAF_read_mem(env, proc->EPROC_base_addr + OFFSET_PROFILE.ts_mm, &mm, sizeof(target_ptr)) < 0)
        return;
    
    if (DECAF_read_mem(env, mm + OFFSET_PROFILE.mm_mmap, &mm_mmap, sizeof(target_ptr)) < 0)
        return;
    
    // Mark the `modules_extracted` true. This is done because this function calls `VMI_find_module_by_base`
    // and that function calls `traverse_mmap` if `modules_extracted` is false. We don't want to get into
    // an infinite recursion.
    proc->modules_extracted = true;
    
    if (-1UL == proc->cr3)
        return;
    
    
    // starting from the first vm_area, read vm_file. NOTICE vm_area_struct can be null
    if (( vma_curr = mm_mmap) == 0)
        return;
    
    
    while(true)
    {
        is_oat = false;
        // read start of curr vma
        if (DECAF_read_mem(env, vma_curr + OFFSET_PROFILE.vma_vm_start, &vma_vm_start, sizeof(target_ptr)) < 0)
            goto next;

		vma_starts.push_back(vma_vm_start);
        // read end of curr vma
        if (DECAF_read_mem(env, vma_curr + OFFSET_PROFILE.vma_vm_end, &vma_vm_end, sizeof(target_ptr)) < 0)
            goto next;

		vma_ends.push_back(vma_vm_end);
		
		if(require_debug != NULL)
			monitor_printf(default_mon,"vma_vm_start %08x vma_vm_end %08x \n",vma_vm_start,vma_vm_end );
		
        // read the struct* file entry of the curr vma, used to then extract the dentry of the this page
        if (DECAF_read_mem(env, vma_curr + OFFSET_PROFILE.vma_vm_file, &vma_file, sizeof(target_ptr)) < 0 || !vma_file)
        {
			//if(require_debug != NULL)
			//	monitor_printf(default_mon, "file_problem - area %08x to %08x\n", proc->comm_name, proc->name, vma_vm_start, vma_vm_end); 
            goto next;
        }
        
        // dentry extraction from the struct* file
        if (DECAF_read_mem(env, vma_file + OFFSET_PROFILE.file_dentry, &f_dentry, sizeof(target_ptr)) < 0 || !f_dentry)
        {
			//if(require_debug != NULL)
			//	monitor_printf(default_mon, "Error 2\n"); 
            goto next;
        }
        
        // read small names form the dentry
       /// if (DECAF_read_mem(env, f_dentry + OFFSET_PROFILE.dentry_d_iname, name, 32) < 0)
       // {
 			//if(require_debug != NULL)
			//	monitor_printf(default_mon, "Error 3\n"); 
            //goto next;
        //}
        
        // inode struct extraction from the struct* file
        if (DECAF_read_mem(env, f_dentry + OFFSET_PROFILE.file_inode, &f_inode, sizeof(target_ptr)) < 0 || !f_inode)
        {
			//if(require_debug != NULL)
			//	monitor_printf(default_mon, "Error 4\n"); 
			//monitor_printf(default_mon, "dentry problem - process %s %s, area %08x to %08x\n", proc->comm_name, proc->name, vma_vm_start, vma_vm_end); 
            goto next;
        }
        
        // inode_number extraction
        if (DECAF_read_mem(env, f_inode + OFFSET_PROFILE.inode_ino, &inode_number , sizeof(unsigned int)) < 0 || !inode_number)
        {
			//if(require_debug != NULL)
			//	monitor_printf(default_mon, "Error 5\n"); 
            goto next;
        }
        
        

		
		//Short name invalid
        if (always_true)
        {
			//try another method to get the name of the file
			target_ulong name_ptr, name_len;
			DECAF_read_mem(env, f_dentry + OFFSET_PROFILE.dentry_d_name + 2 * (sizeof(target_ulong)), &name_ptr, sizeof(target_ulong));
			DECAF_read_mem(env, f_dentry + OFFSET_PROFILE.dentry_d_name + 1 * (sizeof(target_ulong)), &name_len, sizeof(target_ulong));

			++name_len;
			
			name_len = (name_len < 128 )? name_len : 128;
			
			DECAF_read_mem_with_pgd(env, pgd_strip(proc->cr3), name_ptr, name, name_len );
			name[name_len - 1] = '\0';
			
			if(strlen(name) == 0)
			{
				// read small names form the dentry
	       		if (DECAF_read_mem(env, f_dentry + OFFSET_PROFILE.dentry_d_iname, name, 32) < 0)
	        		{
	      		  		goto next;
	        		}
				name[31] = '\0';	// truncate long string
			}

			if((strstr(name, "data@") != NULL || strstr(name, "system@") != NULL) && (strstr(name, "art") == NULL))
            	is_oat = true;
        }

	if(require_debug != NULL)
		monitor_printf(default_mon, "module_name %s\n", name); 

					
        if (!strcmp(last_mod_name.c_str(), name))
        {
            // extending the module
            if(last_vm_end == vma_vm_start)
            {
                assert(mod);
				//target_ulong to_add_size = vma_vm_end - vma_vm_start;
				//mod->size += to_add_size;
				
				target_ulong new_size = vma_vm_end - mod_vm_start;
                if (mod->size < new_size)
                   mod->size = new_size;
            }
            // This is a special case when the data struct is BEING populated
            goto next;
        }
        
        char key[32+256];
        //not extending, a different module
        mod_vm_start = vma_vm_start;
        
        sprintf(key, "%u_%s", inode_number, name);
        mod = VMI_find_module_by_key(key);
        module_bases.insert(vma_vm_start);
        if (!mod)
        {
            mod = new module();
            strncpy(mod->name, name, 64);
            mod->name[127] = '\0';
            mod->is_oat = is_oat;
            mod->size = vma_vm_end - vma_vm_start;
            mod->inode_number = inode_number;
            mod->symbols_extracted = 0;
            //monitor_printf(default_mon,"module %s base %08x \n",mod->name,vma_vm_start);
            VMI_add_module(mod, key);
        }
        
        if(VMI_find_module_by_base(proc->cr3, mod_vm_start) != mod)
        {
            VMI_insert_module(proc->pid, mod_vm_start , mod);
        }
        
  next:
        if (DECAF_read_mem(env, vma_curr + OFFSET_PROFILE.vma_vm_next, &vma_next, sizeof(target_ptr)) < 0)
            break;
        
        if (vma_next == 0x00 /* NULL */)
        {
            break;
        }
        
        vma_curr = vma_next;
        last_mod_name = name;
        if (mod != NULL)
        {
            last_vm_start = vma_vm_start;
            last_vm_end = vma_vm_end;
        }
    }


	// Now that we are done, need to add the stack. //
	#if 0
	target_ulong stack_start, stack_end, index;
	index = vma_starts.size() - 1;
	stack_end = vma_ends[index];
	while(true)
	{ 
		if(vma_starts[index] != vma_ends[index - 1])
			break;

		--index;
	}
	stack_start = vma_starts[index];

	mod = new module();
    strcpy(mod->name, "[stack]");
    mod->size = stack_end - stack_start;
    mod->symbols_extracted = 0;

	if(VMI_find_module_by_base(proc->cr3, stack_start) != mod)
    {
       VMI_insert_module(proc->pid, stack_start , mod);
	}

	module_bases.insert(stack_start);
    // Stack added //
#endif
	
    unordered_map<target_ulong, module *>::iterator iter = proc->module_list.begin();
    set<target_ulong> bases_to_remove;
    for(; iter!=proc->module_list.end(); iter++)
    {
        //DEBUG-only
        //monitor_printf(default_mon,"module %s base %08x \n",iter->second->name,iter->first);
        if (module_bases.find(iter->first) == module_bases.end())
            bases_to_remove.insert(iter->first);
    }
    
    set<target_ulong>::iterator iter2;
    for (iter2=bases_to_remove.begin(); iter2!=bases_to_remove.end(); iter2++)
    {
        VMI_remove_module(proc->pid, *iter2);
    }
}

//New process callback function
static void new_proc_callback(DECAF_Callback_Params* params)
{
    CPUArchState *env = params->bb.env;
    target_ulong pc = DECAF_getPC(env);
    
    if(OFFSET_PROFILE.proc_fork_connector != pc)
    	return;
    
    traverse_task_struct_add(env);
}

//Process exit callback function
static void proc_end_callback(DECAF_Callback_Params *params)
{
    CPUArchState *env = params->bb.env;
    
    target_ulong pc = DECAF_getPC(env);
    
    if(OFFSET_PROFILE.proc_exit_connector != pc)
    return;
    
    traverse_task_struct_remove(env);
}

// Callback corresponding to `vma_link`,`vma_adjust` & `remove_vma`
// This marks the `modules_extracted` for the process `false`
void VMA_update_func_callback(DECAF_Callback_Params *params)
{
    CPUArchState *env = params->bb.env;
    
    target_ulong pc = DECAF_getPC(env);
    
    if(!(pc == OFFSET_PROFILE.vma_link) && !(pc == OFFSET_PROFILE.vma_adjust) && !(pc == OFFSET_PROFILE.remove_vma))
    	return;
    
    target_ulong pgd =  DECAF_getPGD(env);
    process *proc = NULL;
    
    proc = VMI_find_process_by_pgd(pgd);
    
    if(proc)
    {
   		proc->modules_extracted = false;
		traverse_mmap(env, proc);
    }
}

// TLB miss callback
// This callback is only used for updating modules when users have registered for either a
// module loaded/unloaded callback.
void Linux_tlb_call_back(DECAF_Callback_Params *temp)
{
    CPUArchState *ourenv = temp->tx.env;
    target_ulong pgd = -1;
    process *proc = NULL;
    
    // Check to see if any callbacks are registered
    if(!VMI_is_MoudleExtract_Required())
    {
        return;
    }
    
    // The first time we register for some VMA related callbacks
    if(first)
    {
        monitor_printf(default_mon,"Registered for VMA update callbacks!\n");
        DECAF_registerOptimizedBlockBeginCallback(&VMA_update_func_callback, OFFSET_PROFILE.vma_adjust, OCB_CONST);
        DECAF_registerOptimizedBlockBeginCallback(&VMA_update_func_callback, OFFSET_PROFILE.vma_link, OCB_CONST);
        DECAF_registerOptimizedBlockBeginCallback(&VMA_update_func_callback, OFFSET_PROFILE.remove_vma, OCB_CONST);
        first = false;
    }
    
    pgd = DECAF_getPGD(ourenv);
    proc = VMI_find_process_by_pgd(pgd);
    
    // Traverse memory map for a process if required.
    if (proc && !proc->modules_extracted)
    {
        traverse_mmap(ourenv, proc);
    }
}


// to see whether this is a Linux or not,
// the trick is to check the init_thread_info, init_task
int find_linux(CPUArchState *env, uintptr_t insn_handle)
{
    target_ulong _thread_info = DECAF_getESP(env) & ~ (guestOS_THREAD_SIZE - 1);
    static target_ulong _last_thread_info = 0;
    
    // if current address is tested before, save time and do not try it again
    if (_thread_info == _last_thread_info || _thread_info <= 0x80000000)
        return 0;
    // first time run
    if (_last_thread_info == 0)
    {
        // memset(&OFFSET_PROFILE.init_task_addr, -1, sizeof(ProcInfo) - sizeof(OFFSET_PROFILE.strName));
    }
    
    _last_thread_info = _thread_info;
    
    
    
    if(0 != load_proc_info(env, _thread_info, OFFSET_PROFILE))
    {
        return 0;
    }
    
    monitor_printf(default_mon, "swapper task @ [%08x] \n", OFFSET_PROFILE.init_task_addr);
    
    VMI_guest_kernel_base = 0xc0000000;
    
    return (1);
}


// when we know this is a linux
void linux_vmi_init()
{
    DECAF_registerOptimizedBlockBeginCallback(&new_proc_callback, OFFSET_PROFILE.proc_fork_connector, OCB_CONST);
    DECAF_registerOptimizedBlockBeginCallback(&proc_end_callback, OFFSET_PROFILE.proc_exit_connector, OCB_CONST);
    DECAF_registerOptimizedBlockBeginCallback(&VMA_update_func_callback, OFFSET_PROFILE.vma_adjust, OCB_CONST);
    DECAF_registerOptimizedBlockBeginCallback(&VMA_update_func_callback, OFFSET_PROFILE.vma_link, OCB_CONST);
    DECAF_registerOptimizedBlockBeginCallback(&VMA_update_func_callback, OFFSET_PROFILE.remove_vma, OCB_CONST);
    //DECAF_register_callback(DECAF_TLB_EXEC_CB, Linux_tlb_call_back, NULL);
}


gpa_t mips_get_cur_pgd(CPUArchState *env)
{
    const target_ulong MIPS_KERNEL_BASE = 0x80000000;
    gpa_t pgd = 0;
    if(0 == OFFSET_PROFILE.mips_pgd_current)
    {
        monitor_printf(default_mon, "Error\nmips_get_cur_pgd: read pgd before procinfo is populated.\n");
        return 0;
    }
    
    DECAF_read_ptr(env,
    OFFSET_PROFILE.mips_pgd_current,
    &pgd);
    pgd &= ~MIPS_KERNEL_BASE;
    return pgd;
}


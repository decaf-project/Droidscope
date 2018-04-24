/*
 * vmi_c_wraper.c
 *
 *  Created on: Dec 11, 2013
 *      Author: hu
 */

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
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
//#include "sqlite3/sqlite3.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH

#ifdef __cplusplus
};
#endif /* __cplusplus */


#include "DECAF_shared/vmi.h"
#include "DECAF_shared/DECAF_main.h"
#include "DECAF_shared/utils/SimpleCallback.h"
#include "monitor/monitor.h"

#include "linux_vmi_.h"
#include "vmi_c_wrapper.h"

// TODO: WILL BE ADDED SLOWLY  -avb
//#include "DECAF_shared/utils/Output.h"
//#include "DECAF_shared/hookapi.h"
//#include "DECAF_shared/function_map.h"
//#include "windows_vmi.h"
//#include "linux_vmi.h"
//#include "hookapi.h"


using namespace std;
//using namespace std::tr1;

//#ifdef CONFIG_VMI_ENABLE
//keep the sized same with that defined in vmi.h
#define MODULE_NAME_SIZE 128
#define MODULE_FULLNAME_SIZE 256
#define PROCESS_NAME_SIZE 16

#define DECAF_printf(...) monitor_printf(default_mon, __VA_ARGS__)




int  VMI_locate_module_c(gva_t eip, gva_t cr3, char proc[],tmodinfo_t *tm)
{
	module *m;
	process *p;
    gva_t base = 0;

    p = VMI_find_process_by_pgd(cr3);
    if (!p)
    	return -1;

	m = VMI_find_module_by_pc(eip, cr3, &base);
	if(!m)
		return -1;
	strncpy(tm->name, m->name, MODULE_NAME_SIZE ) ;
	strncpy(proc, p->name, sizeof(p->name));
	tm->base = base;
	tm->size = m->size;
	tm->is_oat = m->is_oat;
	return 0;

}

int VMI_locate_module_byname_c(const char *name, uint32_t pid,tmodinfo_t * tm)
{
	module * m = NULL;
	process * p = NULL;
	gva_t base = 0;

	if (!tm) {
		DECAF_printf("tm is NULL\n");
		return -1;
	}
    p = VMI_find_process_by_pid(pid);
    if(!p)
    	return -1;
    m = VMI_find_module_by_name(name, p->cr3,&base);
    if(!m)
    	return -1;
	strncpy(tm->name,m->name, MODULE_NAME_SIZE ) ;
	tm->base = base;
	tm->size = m->size ;
	return 0;

}


int VMI_find_cr3_by_pid_c(uint32_t pid)
{
	process * p = NULL;
	p = VMI_find_process_by_pid(pid);
	if(!p)
		return -1;
	return p->cr3;

}

int VMI_find_pid_by_cr3_c(uint32_t cr3)
{
	process * p = NULL;
	p  = VMI_find_process_by_pgd(cr3);
	if(!p)
		return -1;
	return p->pid;
}

int VMI_find_pid_by_name_c(const char* proc_name)
{
	process *p = NULL;
	p = VMI_find_process_by_name(proc_name);
	if(!p)
		return -1;
	return p->pid;
}


int VMI_find_process_by_cr3_c(uint32_t cr3, char proc_name[], size_t len, uint32_t *pid)
{
	process *p = NULL;
	p = VMI_find_process_by_pgd(cr3);
	if(!p)
		return -1;
	if(len > PROCESS_NAME_SIZE)
		strncpy(proc_name,p->name,PROCESS_NAME_SIZE);
	else
		strncpy(proc_name,p->name,len);
	*pid = p->pid;

	return 0;

}

int VMI_find_process_by_pid_c(uint32_t pid, char proc_name[], size_t len, uint32_t *cr3)
{
	process *p = NULL;
	p = VMI_find_process_by_pid(pid);
	if(!p)
		return -1;
	if(len > PROCESS_NAME_SIZE)
		strncpy(proc_name,p->name,PROCESS_NAME_SIZE);
	else
		strncpy(proc_name,p->name,len);
	*cr3 = p->cr3;

	return 0;

}
int VMI_get_loaded_modules_count_c(uint32_t pid)
{
	process *p = NULL;
	p = VMI_find_process_by_pid(pid);
	if(!p)
		return -1;
	return p->module_list.size();

}
int VMI_get_proc_modules_c(uint32_t pid, uint32_t mod_no, tmodinfo_t *buf)
{
	   process *p = NULL;
	   p = VMI_find_process_by_pid(pid);
	   module * m = NULL;
	   if(!p)
		   return -1;
		unordered_map<uint32_t, module *>::iterator iter;
		uint32_t index = 0;
		for (iter = p->module_list.begin(); iter != p->module_list.end();
				iter++) {
			 m = iter->second;
			 buf[index].size = m->size;
			 buf[index].base = iter->first;
			 strncpy(buf[index].name, m->name, MODULE_NAME_SIZE);
			 index ++;
		}
		return 0;

}
int VMI_get_all_processes_count_c(void)
{
	return process_map.size();
}

int VMI_find_all_processes_info_c(size_t num_proc, procinfo_t *arr)
{
	    unordered_map < uint32_t, process * >::iterator iter;
	    size_t nproc;
	    uint32_t idx = 0;
	    nproc = process_map.size();
	    if(num_proc != nproc)
	    {
	    	DECAF_printf("num_proc is not the same with current process number\n");
	    	return -1;
	    }
	    if(arr){
	    	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
	    		process * proc = iter->second;
	    		arr[idx].cr3 = proc->cr3;
	    		arr[idx].pid = proc->pid;
	    		arr[idx].n_mods = proc->module_list.size();
	    		strncpy(arr[idx].name, proc->name,PROCESS_NAME_SIZE);
	    		arr[idx].name[511] = '\0';
	    		idx++;
	    	}
	    }
	    return 0;

}

int VMI_list_processes(Monitor *mon)
{
	process *proc;
	unordered_map<uint32_t, process *>::iterator iter;

	monitor_printf(mon, "PID\t%08s\t%30s\t\t%15s\n","CR3","Full Name", "Comm Name");
	
	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
		proc = iter->second;
		monitor_printf(mon, "%d\t0x%08x\t%30s\t\t%15s\n", proc->pid, proc->cr3,
				proc->name, proc->comm_name);
	}

	return 0;
}


int VMI_list_modules(Monitor *mon, uint32_t pid) {
	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	if (iter == process_pid_map.end())
	{
		monitor_printf(default_mon,"pid not found\n");
		//pid not found
		return -1;
	}

	unordered_map<uint32_t, module *>::iterator iter2;
	process *proc = iter->second;
	CPUState *here_env = reinterpret_cast<CPUState *>(mon_get_cpu_external(mon));

	if(!proc->modules_extracted)
		traverse_mmap((CPUArchState *)(here_env->env_ptr), proc);

	map<uint32_t, module *> modules;
	map<uint32_t, module *>::iterator iter_m;

	for (iter2 = proc->module_list.begin(); iter2 != proc->module_list.end();
			iter2++) {
		modules[iter2->first] = iter2->second;
	}

	monitor_printf(mon, "%60s\t\t%10s\t%10s\t\t%10s\t\t%10s\n", "Module Name", "Base",
			"Size", "Inode No", "IsOAT?");

	for (iter_m = modules.begin(); iter_m!=modules.end(); iter_m++) {
		module *mod = iter_m->second;
		uint32_t base = iter_m->first;
		monitor_printf(mon, "%60s\t\t0x%08x\t%10d\t\t0x%08x\t\t%10s\n", mod->name, base,
			mod->size, mod->inode_number, mod->is_oat ? "true" : "false");
	}


	return 0;
}


int VMI_get_guest_version_c(void)
{
	if(VMI_guest_kernel_base ==0x80000000)
		return 1;//windows
	else if(VMI_guest_kernel_base == 0xC0000000)
		return 2;//linux
	return 0;//unknown
}

//#endif /*CONFIG_VMI_ENABLE*/

/*
 * vmi.h
 *
 *  Created on: Jan 22, 2013
 *      Author: Heng Yin
 */



#ifndef VMI_H_
#define VMI_H_

#include <iostream>
#include <list>
#include <unordered_map>
#include <unordered_set>
#include "monitor/monitor.h"


//#ifdef CONFIG_VMI_ENABLE
using namespace std;
//using namespace std::tr1;

#define VMI_MAX_MODULE_PROCESS_NAME_LEN 128
#define VMI_MAX_MODULE_FULL_NAME_LEN 256
#define VMI_MAX_PROCESS_NAME_FULL 128

class module{
public:
	char name[VMI_MAX_MODULE_PROCESS_NAME_LEN];
	char fullname[VMI_MAX_MODULE_FULL_NAME_LEN];
	target_ulong size;
	target_ulong codesize; // use these to identify dll
	target_ulong checksum;
	uint16_t major;
	uint16_t minor;
	bool symbols_extracted;
	bool is_oat;
	unordered_map < target_ulong, string> function_map_offset;
	unordered_map < string, target_ulong> function_map_name;
	unsigned int inode_number;

	module()
	{
		this->is_oat = false;
		this->inode_number = 0;
	}
};


class process{
public:
    target_ulong cr3;
    target_ulong pid;
    target_ulong parent_pid;
    target_ulong EPROC_base_addr;
    char comm_name[VMI_MAX_MODULE_PROCESS_NAME_LEN];
	char name[VMI_MAX_PROCESS_NAME_FULL];
    bool modules_extracted;
	bool resolved;
    //map base address to module pointer
    unordered_map < target_ulong,module * >module_list;
    //a set of virtual pages that have been resolved with module information
    unordered_set< target_ulong > resolved_pages;
    unordered_map< target_ulong, int > unresolved_pages;
};



typedef enum {
	WINXP_SP2_C = 0, WINXP_SP3_C, WIN7_SP0_C, WIN7_SP1_C, LINUX_GENERIC_C,
} GUEST_OS_C;


typedef struct os_handle_c{
	GUEST_OS_C os_info;
	int (*find)(CPUState *env,uintptr_t insn_handle);
	void (*init)();
} os_handle_c;

extern target_ulong VMI_guest_kernel_base;

extern unordered_map < target_ulong, process * >process_map;
extern unordered_map < target_ulong, process * >process_pid_map;
extern unordered_map < string, module * >module_name;

module * VMI_find_module_by_pc(target_ulong pc, target_ulong pgd, target_ulong *base);

module * VMI_find_next_module(target_ulong pc, target_ulong pgd, target_ulong *base, target_ulong *prev_base);

module * VMI_find_module_by_name(const char *name, target_ulong pgd, target_ulong *base);

module * VMI_find_module_by_base(target_ulong pgd, target_ulong base);

process * VMI_find_process_by_pid(target_ulong pid);

process * VMI_find_process_by_pgd(target_ulong pgd);

process* VMI_find_process_by_name(const char *name);

process* VMI_find_process_by_comm_name(const char *name);

// add one module
int VMI_add_module(module *mod, const char *key);
// find module by key
module* VMI_find_module_by_key(const char *key);

module* VMI_find_module_by_name_slow(const char *name);

//AVB
int VMI_extract_symbols(module *mod, target_ulong base);

int VMI_create_process(process *proc, bool callback_also);
void VMI_process_callback_only(process *proc);
int VMI_remove_process(target_ulong pid);
int VMI_update_name(target_ulong pid, char *name);
int VMI_remove_all();
int VMI_insert_module(target_ulong pid, uint32_t base, module *mod);
int VMI_remove_module(target_ulong pid, uint32_t base);
int VMI_dipatch_lmm(process *proc);
int VMI_dispatch_lm(module * m,process *proc, target_ulong base);
int VMI_is_MoudleExtract_Required();

extern "C" void VMI_init();
extern "C" int procmod_init();
extern "C" void handle_guest_message(const char *message);
#endif /* VMI_H_ */

//#endif /*CONFIG_VMI_ENABLE*/

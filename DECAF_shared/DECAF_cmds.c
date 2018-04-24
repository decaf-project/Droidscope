/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

#include "DECAF_cmds.h"
#include "DECAF_main.h"
#include "monitor/monitor.h"

//#include "procmod.h"
#include "vmi_c_wrapper.h"


#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)

void do_guest_ps(Monitor *mon)
{
  //list_procs(mon);
  //linux_ps(mon);
  VMI_list_processes(mon);
}

void do_guest_pt(Monitor* mon)
{
  //linux_pt(mon);
}

void do_guest_modules(Monitor* mon, int pid)
{
  //linux_print_mod(mon, pid); 
  VMI_list_modules(mon, (uint32_t)pid);
}

void do_guest_symbols(Monitor* mon, char *module_name, int pid, int base)
{
  VMI_list_symbols(mon, module_name, pid, base);
}
void do_sym_to_addr(Monitor* mon, int pid, const char* modName, const char* symName)
{
  //get_symbol_address(mon, pid, modName, symName);
}

void do_memsave(Monitor* mon, int vaddr, int size, int pgd, const char *dest_file)
{
	FILE *out_file = fopen(dest_file, "a+");
	CPUState *cpu = mon_get_cpu_external(mon);
	CPUArchState *env = cpu->env_ptr;
    uint32_t l;
	uint8_t buf[1024];
	
	
	if(!out_file) {
		monitor_printf(mon, "fopen() error\n");
		goto exit;
	}

	while (size != 0) {
        l = sizeof(buf);
        if (l > size)
            l = size;
		
		//cpu_physical_memory_rw(vaddr, buf, l, 0);
        //cpu_memory_rw_debug(env, vaddr, buf, l, 0);
		DECAF_read_mem_with_pgd(env,pgd_strip(pgd),vaddr,buf,l);
		//DECAF_read_mem(env,vaddr,buf,l);
        if (fwrite(buf, 1, l, out_file) != l) {
            monitor_printf(mon, "fwrite() error in do_memory_save\n");
            goto exit;
        }
        vaddr += l;
        size -= l;
    }


exit:
    fclose(out_file);
    return;
		
}



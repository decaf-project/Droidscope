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
 * linux_procinfo.cpp
 *
 *  Created on: September, 2013
 *      Author: Kevin Wang, Lok Yan
 */

#include <inttypes.h>
#include <string>
#include <list>
#include <vector>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unordered_map>
#include <unordered_set>

#include <boost/foreach.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/lexical_cast.hpp>

#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <queue>
#include <sys/time.h>
//#include <math.h>
//#include <glib.h>
#include <mcheck.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH
#include "DECAF_main.h"
//#include "DECAF_target.h"
#ifdef __cplusplus
};
#endif /* __cplusplus */

/* AVB - introduced slowly
#include "hookapi.h"
#include "function_map.h"
*/

#include "DECAF_shared/linux_procinfo.h"
#include "DECAF_shared/vmi.h"
#include "DECAF_shared/DECAF_main.h"
#include "DECAF_shared/utils/SimpleCallback.h"



#ifdef TARGET_I386
  #define T_FMT ""
  #define PI_R_EAX "eax"
  #define PI_R_ESP "esp"
/*
  #define isPrintableASCII(_x) ( ((_x & 0x80808080) == 0)   \
                                && ((_x & 0xE0E0E0E0) != 0) )
*/
#elif defined(TARGET_ARM)
  #define T_FMT ""
  #define PI_R_EAX "r0"
  #define PI_R_ESP "sp"

/*
  #define isPrintableASCII(_x) ( ((_x & 0x80808080) == 0)   \
                                && ((_x & 0xE0E0E0E0) != 0) )
*/
#else
  #define T_FMT "ll"
  #define PI_R_EAX "rax"
  #define PI_R_ESP "rsp"
/*
  #define isPrintableASCII(_x) ( ((_x & 0x8080808080808080) == 0)   \
                                && ((_x & 0xE0E0E0E0E0E0E0E0) != 0) )
*/
#endif

//Here are some definitions straight from page_types.h

#define INV_ADDR ((target_ulong) -1)
#define INV_OFFSET ((target_ulong) -1)
#define INV_UINT ((target_uint) -1)

#if defined(TARGET_I386) || defined(TARGET_ARM)//  || defined(TARGET_MIPS)
  //this is the default value - but keep in mind that a custom built
  // kernel can change this
  #define TARGET_PAGE_OFFSET 0xC0000000

  //defined this extra constant here so that the code
  // for isKernelAddress can be standardized
  #define TARGET_KERNEL_IMAGE_START TARGET_PAGE_OFFSET
  #define TARGET_MIN_STACK_START 0xA0000000 //trial and error?
  #define TARGET_KERNEL_IMAGE_SIZE (0)
#elif defined(TARGET_MIPS)
  #define TARGET_PAGE_OFFSET  0x80000000UL
  #define TARGET_KERNEL_IMAGE_START TARGET_PAGE_OFFSET
  #define TARGET_MIN_STACK_START 0xA0000000UL //trial and error?
  #define TARGET_KERNEL_IMAGE_SIZE (0)
#else
  //See: http://lxr.linux.no/#linux+v3.11/Documentation/x86/x86_64/mm.txt
  // for the memory regions
  //These ranges seem to work for 2.6.32 as well
  //these definitions are in page_64_types.h

  //2.6.28 uses 81 to c0ffff -- 46bits of memory
  //2.6.29 uses 88 - c0ffff -- 57TB it says
  //2.6.31 uses 88 - c7ffff -- 64tb of memory - man they sure like to change these things!!!!
  #define TARGET_PAGE_OFFSET  0xFFFF880000000000
 
  //this is consistent from 2.6.28
  #define TARGET_KERNEL_IMAGE_START 0xFFFFFFFF80000000
  #define TARGET_MIN_STACK_START 0x0000000100000000 //trial and error?
  #define TARGET_KERNEL_IMAGE_SIZE (512 * 1024 * 1024)
#endif //target_i386


//straight from the kernel in processor.h
#define TARGET_TASK_SIZE TARGET_PAGE_OFFSET
#define TARGET_KERNEL_START TARGET_TASK_SIZE

#if defined(TARGET_I386) 
  //got this value from testing - not necessarily true though
  //might be some devices mapped into physical memory
  // that will screw things up a bit
  #define TARGET_KERNEL_END (0xF8000000 - 1)
#elif defined(TARGET_ARM)
  // NOTICE in ARM when RAM size is less than 896, then high_memory is equal to actual RAM size
  // check this link: http://www.arm.linux.org.uk/developer/memory.txt
  #define TARGET_KERNEL_END (TARGET_PAGE_OFFSET + ((ram_size < 896 * 1024 * 1024) ? (ram_size - 1) : (0xF8000000 - 1)))
#else
  //same here - in fact the global stuff (from the kernel image) are defined in higher addresses
  #define TARGET_KERNEL_END 0xFFFFC80000000000
#endif //target_i386

//some definitions to help limit how much to search
// these will likely have to be adjusted for 64 bit, 20, 4k and 100 works for 32
#define MAX_THREAD_INFO_SEARCH_SIZE 20
#define MAX_TASK_STRUCT_SEARCH_SIZE 4000 
#define MAX_MM_STRUCT_SEARCH_SIZE 500
#define MAX_VM_AREA_STRUCT_SEARCH_SIZE 500
#define MAX_CRED_STRUCT_SEARCH_SIZE 200
#define MAX_DENTRY_STRUCT_SEARCH_SIZE 200

//the list head contains two pointers thus
#define SIZEOF_LIST_HEAD (sizeof(target_ptr) + sizeof(target_ptr))
#define SIZEOF_COMM ((target_ulong)16)

#define TARGET_PGD_MASK TARGET_PAGE_MASK
#define TARGET_PGD_TO_CR3(_pgd) (_pgd - TARGET_KERNEL_START) //this is a guess



int printProcInfo(ProcInfo* pPI)
{
  if (pPI == NULL)
  {
    return (-1);
  }

  monitor_printf(default_mon,
      "    {  \"%s\", /* entry name */\n"
      "       0x%08"T_FMT"X, /* init_task address */\n"
      "       %"T_FMT"d, /* size of task_struct */\n"
      "       %"T_FMT"d, /* offset of task_struct list */\n"
      "       %"T_FMT"d, /* offset of pid */\n"
      "       %"T_FMT"d, /* offset of tgid */\n"
      "       %"T_FMT"d, /* offset of group_leader */\n"
      "       %"T_FMT"d, /* offset of thread_group */\n"
      "       %"T_FMT"d, /* offset of real_parent */\n"
      "       %"T_FMT"d, /* offset of mm */\n"
      "       %"T_FMT"d, /* offset of stack */\n"
      "       %"T_FMT"d, /* offset of real_cred */\n"
      "       %"T_FMT"d, /* offset of cred */\n"
      "       %"T_FMT"d, /* offset of comm */\n"
      "       %"T_FMT"d, /* size of comm */\n",
	  "       %"T_FMT"d, /* inode index number*/\n",
      pPI->strName,
      pPI->init_task_addr,
      pPI->init_task_size,
      pPI->ts_tasks,
      pPI->ts_pid,
      pPI->ts_tgid,
      pPI->ts_group_leader,
      pPI->ts_thread_group,
      pPI->ts_real_parent,
      pPI->ts_mm,
      pPI->ts_stack,
      pPI->ts_real_cred,
      pPI->ts_cred,
      pPI->ts_comm,
      SIZEOF_COMM,
      pPI->inode_ino
  );

  monitor_printf(default_mon,
      "       %"T_FMT"d, /* offset of uid cred */\n"
      "       %"T_FMT"d, /* offset of gid cred */\n"
      "       %"T_FMT"d, /* offset of euid cred */\n"
      "       %"T_FMT"d, /* offset of egid cred */\n",
      pPI->cred_uid,
      pPI->cred_gid,
      pPI->cred_euid,
      pPI->cred_egid
  );

  monitor_printf(default_mon,
      "       %"T_FMT"d, /* offset of mmap in mm */\n"
      "       %"T_FMT"d, /* offset of pgd in mm */\n"
      "       %"T_FMT"d, /* offset of arg_start in mm */\n"
      "       %"T_FMT"d, /* offset of start_brk in mm */\n"
      "       %"T_FMT"d, /* offset of brk in mm */\n"
      "       %"T_FMT"d, /* offset of start_stack in mm */\n",
      pPI->mm_mmap,
      pPI->mm_pgd,
      pPI->mm_arg_start,
      pPI->mm_start_brk,
      pPI->mm_brk,
      pPI->mm_start_stack
  );

  monitor_printf(default_mon,
      "       %"T_FMT"d, /* offset of vm_start in vma */\n"
      "       %"T_FMT"d, /* offset of vm_end in vma */\n"
      "       %"T_FMT"d, /* offset of vm_next in vma */\n"
      "       %"T_FMT"d, /* offset of vm_file in vma */\n"
      "       %"T_FMT"d, /* offset of vm_flags in vma */\n",
      pPI->vma_vm_start,
      pPI->vma_vm_end,
      pPI->vma_vm_next,
      pPI->vma_vm_file,
      pPI->vma_vm_flags
  );

  monitor_printf(default_mon,
      "       %"T_FMT"d, /* offset of dentry in file */\n"
      "       %"T_FMT"d, /* offset of d_name in dentry */\n"
      "       %"T_FMT"d, /* offset of d_iname in dentry */\n"
      "       %"T_FMT"d, /* offset of d_parent in dentry */\n",
      pPI->file_dentry,
      pPI->dentry_d_name,
      pPI->dentry_d_iname,
      pPI->dentry_d_parent
  );

  monitor_printf(default_mon,
      "       %"T_FMT"d, /* offset of task in thread info */\n",
      pPI->ti_task
  );

  return (0);
}

void get_executable_directory(string &sPath)
{
  int rval;
  char szPath[1024];
  sPath = "";
  rval = readlink("/proc/self/exe", szPath, sizeof(szPath)-1);
  if(-1 == rval)
  {
    monitor_printf(default_mon, "can't get path of main executable.\n");
    return;
  }
  szPath[rval-1] = '\0';
  sPath = szPath;
  sPath = sPath.substr(0, sPath.find_last_of('/'));
  sPath += "/";
  return;
}

void get_procinfo_directory(string &sPath)
{
  get_executable_directory(sPath);
  sPath += "../DECAF_shared/kernelinfo/";
  return;
}

// given the section number, load the offset values
#define FILL_TARGET_ULONG_FIELD(field) pi.field = pt.get(sSectionNum + #field, INVALID_VAL)
void _load_one_section(const boost::property_tree::ptree &pt, int iSectionNum, ProcInfo &pi)
{
    string sSectionNum;

    sSectionNum = boost::lexical_cast<string>(iSectionNum);
    sSectionNum += ".";

    // fill strName field
    string sName;
    const int SIZE_OF_STR_NAME = 32;
    sName = pt.get<string>(sSectionNum + "strName");
    strncpy(pi.strName, sName.c_str(), SIZE_OF_STR_NAME);
    pi.strName[SIZE_OF_STR_NAME-1] = '\0';

    const target_ulong INVALID_VAL = -1;

    // fill other fields
    FILL_TARGET_ULONG_FIELD(init_task_addr  );
    FILL_TARGET_ULONG_FIELD(init_task_size  );
    FILL_TARGET_ULONG_FIELD(ts_tasks        );
    FILL_TARGET_ULONG_FIELD(ts_pid          );
    FILL_TARGET_ULONG_FIELD(ts_tgid         );
    FILL_TARGET_ULONG_FIELD(ts_group_leader );
    FILL_TARGET_ULONG_FIELD(ts_thread_group );
    FILL_TARGET_ULONG_FIELD(ts_real_parent  );
    FILL_TARGET_ULONG_FIELD(ts_mm           );
    FILL_TARGET_ULONG_FIELD(ts_stack        );
    FILL_TARGET_ULONG_FIELD(ts_real_cred    );
    FILL_TARGET_ULONG_FIELD(ts_cred         );
    FILL_TARGET_ULONG_FIELD(ts_comm         );
    FILL_TARGET_ULONG_FIELD(cred_uid        );
    FILL_TARGET_ULONG_FIELD(cred_gid        );
    FILL_TARGET_ULONG_FIELD(cred_euid       );
    FILL_TARGET_ULONG_FIELD(cred_egid       );
    FILL_TARGET_ULONG_FIELD(mm_mmap         );
    FILL_TARGET_ULONG_FIELD(mm_pgd          );
    FILL_TARGET_ULONG_FIELD(mm_arg_start    );
    FILL_TARGET_ULONG_FIELD(mm_start_brk    );
    FILL_TARGET_ULONG_FIELD(mm_brk          );
    FILL_TARGET_ULONG_FIELD(mm_start_stack  );
    FILL_TARGET_ULONG_FIELD(vma_vm_start    );
    FILL_TARGET_ULONG_FIELD(vma_vm_end      );
    FILL_TARGET_ULONG_FIELD(vma_vm_next     );
    FILL_TARGET_ULONG_FIELD(vma_vm_file     );
    FILL_TARGET_ULONG_FIELD(vma_vm_flags    );
    FILL_TARGET_ULONG_FIELD(vma_vm_pgoff    );
    FILL_TARGET_ULONG_FIELD(file_dentry     );
		FILL_TARGET_ULONG_FIELD(file_inode		);
    FILL_TARGET_ULONG_FIELD(dentry_d_name   );
    FILL_TARGET_ULONG_FIELD(dentry_d_iname  );
    FILL_TARGET_ULONG_FIELD(dentry_d_parent );
    FILL_TARGET_ULONG_FIELD(ti_task         );
	FILL_TARGET_ULONG_FIELD(inode_ino);
	FILL_TARGET_ULONG_FIELD(async_thread);
	FILL_TARGET_ULONG_FIELD(proc_fork_connector);
	FILL_TARGET_ULONG_FIELD(proc_exit_connector);
	FILL_TARGET_ULONG_FIELD(proc_exec_connector);
	FILL_TARGET_ULONG_FIELD(vma_link);
	FILL_TARGET_ULONG_FIELD(remove_vma);
	FILL_TARGET_ULONG_FIELD(vma_adjust);

#ifdef TARGET_MIPS
    FILL_TARGET_ULONG_FIELD(mips_pgd_current);
#endif
}

// find the corresponding section for the current os and return the section number
int find_match_section(const boost::property_tree::ptree &pt, target_ulong tulInitTaskAddr)
{
    int cntSection = pt.get("info.total", 0);

    string sSectionNum;
    vector<int> vMatchNum;

    monitor_printf(default_mon, "Total Sections: %d\n", cntSection);

    for(int i = 1; i<=cntSection; ++i)
    {
      sSectionNum = boost::lexical_cast<string>(i);
      target_ulong tulAddr = pt.get<target_ulong>(sSectionNum + ".init_task_addr");
      if(tulAddr == tulInitTaskAddr)
      {
        vMatchNum.push_back(i);
      }
    }

    if(vMatchNum.size() > 1)
    {
      monitor_printf(default_mon, "Too many match sections in procinfo.ini\n");
      return 0;
    }

    if(vMatchNum.size() <= 0)
    {
      monitor_printf(default_mon, "No match in procinfo.ini\n");
      return 0;
    }

    return vMatchNum[0];
}


#if 0


//here is a simple function that I wrote for
// use in this kernel module, but you get the idea
// the problem is that not all addresses above
// 0xC0000000 are valid, some are not
// depending on whether the virtual address range is used
// we can figure this out by searching through the page tables
static inline
int isKernelAddress(gva_t addr)
{
  return (
    //the normal kernel memory area
    ( (addr >= TARGET_KERNEL_START) && (addr < TARGET_KERNEL_END) )
    //OR the kernel image area - in case the kernel image was mapped to some
    // other virtual address region - as from x86_64
    || ( (addr >= TARGET_KERNEL_IMAGE_START) && (addr < (TARGET_KERNEL_IMAGE_START + TARGET_KERNEL_IMAGE_SIZE)) )
#ifdef TARGET_X86_64
    //needed to incorporate the vmalloc/ioremap space according to the
    // mm.txt in documentation/x86/x86_64 of the source
    //this change has been incorporated since 2.6.31
    //2.6.30 used c2 - e1ffff as the range.
    || ( (addr >= 0xFFFFC90000000000) && (addr < 0xFFFFe90000000000) )
#endif
  );
}

//The idea is to go through the data structures and find an
// item that points back to the threadinfo
//ASSUMES PTR byte aligned
// gva_t findTaskStructFromThreadInfo(CPUState * env, gva_t threadinfo, ProcInfo* pPI, int bDoubleCheck) __attribute__((optimize("O0")));
gva_t  findTaskStructFromThreadInfo(CPUState * env, gva_t threadinfo, ProcInfo* pPI, int bDoubleCheck)
{
  int bFound = 0;
  target_ulong i = 0;
  target_ulong j = 0;
  gva_t temp = 0;
  gva_t temp2 = 0;
  gva_t candidate = 0;
  gva_t ret = INV_ADDR;

  if (pPI == NULL)
  {
    return (INV_ADDR);
  }

  //iterate through the thread info structure
  for (i = 0; i < MAX_THREAD_INFO_SEARCH_SIZE; i+= sizeof(target_ptr))
  {
    temp = (threadinfo + i);
    candidate = 0;
    // candidate = (get_target_ulong_at(env, temp));
    DECAF_read_ptr(env, temp, &candidate);
    //if it looks like a kernel address
    if (isKernelAddress(candidate))
    {
      //iterate through the potential task struct
      for (j = 0; j < MAX_TASK_STRUCT_SEARCH_SIZE; j+= sizeof(target_ptr))
      {
        temp2 = (candidate + j);
        //if there is an entry that has the same
        // value as threadinfo then we are set
        target_ulong val = 0;
        DECAF_read_ptr(env, temp2, &val);
        if (val == threadinfo)
        {
          if (bFound)
          {
            //printk(KERN_INFO "in findTaskStructFromThreadInfo: Double Check failed\n");
            return (INV_ADDR);
          }

          pPI->ti_task = i;
          pPI->ts_stack = j;
          ret = candidate;

          if (!bDoubleCheck)
          {
            return (ret);
          }
          else
          {
            //printk(KERN_INFO "TASK STRUCT @ [0x%"T_FMT"x] FOUND @ offset %"T_FMT"d\n", candidate, j);
            bFound = 1;
          }
        }
      }
    }
  }
  return (ret);
}
#endif

// infer init_task_addr, use the init_task_addr to search for the corresponding
// section in procinfo.ini. If found, fill the fields in ProcInfo struct.
int load_proc_info(CPUArchState *env, gva_t thread__info, ProcInfo &pi)
{
  static bool bProcinfoMisconfigured = false;
  const int CANNOT_FIND_INIT_TASK_STRUCT = -1;
  const int CANNOT_OPEN_PROCINFO = -2;
  const int CANNOT_MATCH_PROCINFO_SECTION = -3;
  target_ulong tulInitTaskAddr, threadinfo, next_task;
  char swapper_name[512];

  // find init_task_addr
  //tulInitTaskAddr = findTaskStructFromThreadInfo(env, threadinfo, &pi, 0);



  string sProcInfoPath;
  boost::property_tree::ptree pt;
  get_procinfo_directory(sProcInfoPath);
  sProcInfoPath += "procinfo.ini";

  // read procinfo.ini
  if (0 != access(sProcInfoPath.c_str(), 0))
  {
      monitor_printf(default_mon, "can't open %s\n", sProcInfoPath.c_str());
      return CANNOT_OPEN_PROCINFO;
  }
  boost::property_tree::ini_parser::read_ini(sProcInfoPath, pt);

  // find the match section using previously found init_task_addr
  int iSectionNum = 1; //find_match_section(pt, tulInitTaskAddr);
  // no match or too many match sections
  if(0 == iSectionNum)
  {
    monitor_printf(default_mon, "VMI won't work.\nPlease configure procinfo.ini and restart DECAF.\n");
    // exit(0);
    bProcinfoMisconfigured = true;
    return CANNOT_MATCH_PROCINFO_SECTION;
  }

  _load_one_section(pt, iSectionNum, pi);



  threadinfo = DECAF_getESP(env) & ~8191;
  DECAF_read_mem(env, thread__info + pi.ti_task, &tulInitTaskAddr, 4);

	//monitor_printf(default_mon, "init_add_expect = %lu, init_addr_give = %lu\n", pi.init_task_addr, tulInitTaskAddr);
	if(tulInitTaskAddr == pi.init_task_addr)
	{
		next_task = pi.init_task_addr;
	
		monitor_printf(default_mon, "match found!\n");

		if(DECAF_read_mem(env, next_task + pi.ts_comm,
	                                   swapper_name, SIZEOF_COMM) < 0)
		{
			return 0;
		}

		monitor_printf(default_mon, "swapper name = %s!\n", swapper_name);
		
		return 0;
	}
	
	return CANNOT_MATCH_PROCINFO_SECTION;
	
}

void load_library_info(const char *strName)
{

}


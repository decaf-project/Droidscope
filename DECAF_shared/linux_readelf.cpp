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
linux_readelf.cpp

- Abhishek Vasisht Bhaskar (abhaskar@syr.edu)
*/

#include <iostream>
#include <istream>
#include <streambuf>
#include <sstream>
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
#include <mcheck.h>


#ifdef __cplusplus
extern "C" {
    
    #endif /* __cplusplus */
        #include "cpu.h"
    #include "config.h"
    #include "hw/hw.h" // AWH
    #include <cxxabi.h>
    
    #include "block/block.h"
    
    #ifdef __cplusplus
};
#endif /* __cplusplus */
    



#include "DECAF_main.h"
#include "DECAF_shared/vmi.h"
#include "hookapi.h"
#include "function_map.h"
#include "DECAF_shared/utils/SimpleCallback.h"
#include "linux_readelf.h"
//#include <elfio/elfio.hpp>
#include "DECAF_shared/elfio/elfio.hpp"
#include <elfio/elfio_dump.hpp>
#include "DECAF_shared/DECAF_fileio.h"


#if HOST_LONG_BITS == 64
    /* Define BFD64 here, even if our default architecture is 32 bit ELF
as this will allow us to read in and parse 64bit and 32bit ELF files.
Only do this if we believe that the compiler can support a 64 bit
data type.  For now we only rely on GCC being able to do this.  */
#define BFD64
#endif

#define PACKAGE "libgrive"


using namespace ELFIO;


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



// register symbol to DECAF
static void register_symbol(const char * mod_name, const string &func_name,
target_ulong func_addr, target_ulong inode_number)
{
    funcmap_insert_function(mod_name, func_name, func_addr, inode_number);
}



/* Process one ELF object */
int read_elf_info(const char * mod_name, target_ulong start_addr, unsigned int inode_number) {
    

    
    bool header_present;
    TSK_FS_FILE *file_fs = tsk_fs_file_open_meta(disk_info_internal[SYSTEM_PARTITION].fs, NULL, (TSK_INUM_T)inode_number);
    
    void *file_stream = static_cast<void*>(new std::string());
    std::string *local_copy = static_cast<std::string*>(file_stream);
    
    int ret = 0;
    ret = tsk_fs_file_walk(file_fs, TSK_FS_FILE_WALK_FLAG_NONE, write_action, file_stream);
    
    std::istringstream is(*local_copy);
    
    elfio reader;
    Elf64_Addr elf_entry = 0;
    bool found = false;
    header_present = reader.load(is);
    
    
    Elf_Half seg_num = reader.segments.size();
    //elf_entry = reader.get_entry();
    
    //std::cout << "Number of segments: \n";// << seg_num << " Entry: " << elf_entry << std::endl;
    
    
    
    for ( int i = 0; i < seg_num; ++i )
    {
        const segment* pseg = reader.segments[i];
        
        if(pseg->get_type() == PT_LOAD) {
            elf_entry = pseg->get_virtual_address();
            found = true;
        }
        
        if(found)
        break;
    }
    
    
    
    
    Elf_Half n = reader.sections.size();
    
    for ( Elf_Half i = 0; i < n; ++i )
    {    // For all sections
        section* sec = reader.sections[i];
        if ( SHT_SYMTAB == sec->get_type() || SHT_DYNSYM == sec->get_type() )
        {
            symbol_section_accessor symbols( reader, sec );
            
            Elf_Xword     sym_no = symbols.get_symbols_num();
            if ( sym_no > 0 ) {
                for ( Elf_Half i = 0; i < sym_no; ++i )
                {
                    std::string   name;
                    Elf64_Addr    value   = 0;
                    Elf_Xword     size    = 0;
                    unsigned char bind    = 0;
                    unsigned char type    = 0;
                    Elf_Half      section = 0;
                    unsigned char other   = 0;
                    symbols.get_symbol( i, name, value, size, bind, type, section, other );
                    
                    char *demangled_str = NULL;
                    int demangle_result = 1;
                    demangled_str = abi::__cxa_demangle(name.c_str(), NULL, NULL, &demangle_result);
                    if (0 == demangle_result &&
                        NULL != demangled_str)
                    {
                        //std::cout << "name = " << demangled_str << " start_addr = " << value << std::endl;
                        // fprintf(fp, "mod_name=\"%s\" elf_name=\"%s\" base_addr=\"%x\" func_addr= \"%x\" \n",mod_name, demangled_str,elf_entry ,value);
                        
                        register_symbol(mod_name, string(demangled_str), (value-elf_entry), inode_number);
                        free(demangled_str);
                    }
                    else // failed demangle; print it raw
                    {
                        register_symbol(mod_name, name, (value-elf_entry), inode_number);
                        //fprintf(fp, "mod_name=\"%s\" elf_name=\"%s\" base_addr=\"%x\" func_addr= \"%x\" \n",mod_name, name.c_str(),elf_entry ,value);
                    }
                    
                    
                    // fflush(fp);
                }
            }
        }
    }
    //fclose(fp);
    return true;
}




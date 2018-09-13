#ifndef UNPACKER_H
#define UNPACKER_H


#include <sys/time.h>

// #include "DECAF_shared/dalvik_callback.h"
// #include "DECAF_shared/dalvik_vmi.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_shared/vmi_callback.h"
#include "DECAF_shared/DECAF_fileio.h"

#include "vmi_c_wrapper.h"
#include "function_map.h"
#include "vmi.h"
#include "art_vmi.h"
#include <pthread.h>
#include <sys/mman.h>
#include <iostream>
#include <fstream>
#include <ctype.h>

#include <sys/mman.h>
#include <stack>  // std::stack
#include <string>
#include <vector>
#include <algorithm>
#include <map>
#include <set>
#include <sstream>
#include <fstream>
// #include <unordered_map>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <streambuf>
#include <iterator>
#include <algorithm>
#include <stdexcept>
#include <cstdint>
#include "json/json.hpp"

// The hard part
#include "thread.h"
#include "oat_file.h"
#include "dex_file.h"
#include "mirror/art_method.h"
#include "mirror/object_reference.h"
#include "mirror/class.h"
#include "mirror/dex_cache.h"
#include "class_item_iter.h"
#include "hw/android/goldfish/vmem.h"
#include "dex_instruction.h"
#include "oat_file-inl.h"

// #define SIZEOF_TYPE(struct_type) (sizeof(struct_type))
#define pgd_strip(_pgd) (_pgd & ~0xC0000FFF)

#define DECAF_printf(...) monitor_printf(default_mon, __VA_ARGS__)
// #define log_printf(...) fprintf(log_functions, __VA_ARGS__)

#define ARTMETHOD_INVOKE    0
#define INTERPRETER_DOCALL  1
#define NON_INVOKE_CALL     -1

#define JNIMETHOD_START 0
#define JNIMETHOD_END   1
#define ART_FIND_NATIVE_METHOD 2
#define NON_JNIMETHOD   -1


typedef uint8_t byte;
using json = nlohmann::json;

static plugin_interface_t hookapitests_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle insn_begin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle memwrite_handle = DECAF_NULL_HANDLE;
static DECAF_Handle module_load_handle = DECAF_NULL_HANDLE, block_begin_cb_handle = DECAF_NULL_HANDLE;


static char targetname[512];
static char actualname[512];
static char dir_name[] = "/tmp/XXXXXX";
static std::string temp_dir_name;

static std::string dumps_dir = "/home/developer/Droidscope/droidscope/DECAF_plugins/old_dex_extarctor/out/";
static std::string json_path = "/home/developer/Droidscope/droidscope/DECAF_plugins/old_dex_extarctor/out/stats.json";

static target_ulong base, targetpid = 0;
static target_ulong targetcr3 = 0;
static uint32_t current_dex_file = 0;
static uint32_t current_module_file = 0;

// holds all the cr3s of target processes (parent and children)
static unordered_set<target_ulong> targetcr3s;
static unordered_set<target_ulong> targetPids;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// For the following three data structures, first value is always cr3
// holds all pc values of encountered basic block
static unordered_map<target_ulong, unordered_set<target_ulong>> pcSet;
// this data structure holds all the addresses written
// second value = 1 means it is in pcSet, 0 means not pc
//static map<target_ulong, uint8_t> byte_addrs_written;
static unordered_map<target_ulong, map<target_ulong, uint8_t>> byte_addrs_written;

// this set holds all addresses written, and will be cleared during execution for incremental unpacking detection
static unordered_map<target_ulong, unordered_set<target_ulong>> byte_addrs_written_inc;
static uint32_t wave = 0;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

static unordered_set<target_ulong> self_modifying_addrs;

static unordered_map<string, vector<target_ulong>> baseToSizesMapping;

static unordered_map<target_ulong, int> bad_dex_file_bases;

static char* block = NULL;

// Set of page base addresses of dirt memory
static FILE* log_functions, *log_others, *log_modules, *log_mw;
static bool oat_framework_extracted = false;


// switch on/off for logs
static bool PRINT_FRAMEWORK_CALL = true;
static bool debuggingOther = true;
static bool debuggingModule = true;
static bool debuggingFunctions = false;
static bool debuggingMW = false;
static bool dumpCode = false;
static bool dumpLibc = false;


static bool libcDumped = false;
static bool oatDumped = false;

// current env and cr3 info, update in block_cb
static target_ulong current_cr3 = 0x00;
static CPUArchState* current_env = NULL;

////////////////////////////////////////////////////////////////////////////////////////
// 1. JNI Hiding detection:
// current depth of art::JniMethodStart
static uint32_t jniMethodDepth = 0;

// the jniMethodDepth of one native function within the app
static uint32_t jniDepthForJniCall = 0;
static bool withinJNICall = false;

// this bool is used to keep record of what happened in last block callback
// if true, it means that last block is a native function call in the app itself
static bool lastCallNativeInApk = false;
// END JNI Hiding detection
////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////
// 2. Unpacked code storage detection
// hold all the file creation (fd and file name)that is writable (mode contains: w, a, r+)
static unordered_set<std::string> writableFileCreated;
static unordered_set<int> fileDescriptors;
static unordered_set<target_ulong> fileObjectPtrs;

static unordered_set<size_t> mmapedMemoryRegions;

// these variables hold the return address of 'fopen', 'open' and 'mmap' to decide when the functions return
static size_t fopenRetAdr = 0;
static size_t openRetAdr = 0;
static size_t mmapRetAdr = 0;
static size_t fgetsRetAdr = 0;

// this vairable holds the address of 'mmap'ed memory region
static size_t mmapAdr = 0;

// END Unpacked code storage detection
////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////
// 3. Cloaking techniques

//END Cloaking techniques
////////////////////////////////////////////////////////////////////////////////////////




// save string to file
void save_string(std::string& data, std::string& file_name)
{
  	std::ofstream out(file_name);
  	out << data;
  	out.close();
}


std::string get_string(std::string& file_name)
{
  	std::ifstream t(file_name);
  	std::string str((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
  	t.close();
  	return std::move(str);
}


void jsonInit()
{
	json jsonItems = 
	{
		{"hash", ""},
		{"dirty_native_code", ""},
		{"dirty_dalvik_code", ""},
		{"packer", ""},
		{"num_native_methods", 0},
		{"num_dalvik_methods", 0},
		{"num_dirty_native_methods", 0},
		{"num_dirty_dalvik_methods", 0},
		{"child_processes", 0},
		{"wave", 0},
		{"self_modifying", ""},
		{"self_modifying_in_dex", ""},
		{"incremental_unpacking", ""},
		{"jni_hiding", ""},
		{"dex_file_integrity", ""},
		{"anti-debug", ""},
		{"anti-emulation", ""},
		{"file_storage", ""},
		{"code_loading_method", ""},
		{"packed", ""}
	};
	    
	std::string s = jsonItems.dump(0);
    save_string(s, json_path);
}


// this function sets 'str' in json file with value 'value'
void setInJson(std::string str, std::string val)
{
  	auto j3 = json::parse(get_string(json_path));
 	std::string preVal = j3[str];

 	if(preVal == val)
 		return;

 	std::string newVal;

 	if(preVal.empty())
 		newVal = val;
 	else
 		newVal = preVal + ", "  + val;

 	// std::cout << str << " has value: " << preVal;
 	// std::cout << " is changing value to: " << newVal << std::endl;

  	j3[str] = newVal;
  	std::string s = j3.dump(0);
  	save_string(s, json_path);
}

std::string getValFromJson(std::string str)
{
	auto j3 = json::parse(get_string(json_path));
 	std::string val = j3[str];
 	return val;
}


// read from the json file and increment the given value by 1
void increment_something(std::string value)
{
  	auto j3 = json::parse(get_string(json_path));
  	int num = j3[value];
  	j3[value] = num + 1;
  	std::string s = j3.dump();
  	save_string(s, json_path);
}


// these two functions judge if a given function is the right function we want
int is_an_invoke_call(char* functionname)
{
  	if (strstr(functionname, "art::mirror::ArtMethod::Invoke"))
    	return ARTMETHOD_INVOKE;
  	else if (strstr(functionname, "art::interpreter::DoCall"))
    	return INTERPRETER_DOCALL;
  	else
    	return NON_INVOKE_CALL;
}

int isJniMethodFunc(char* functionname)
{
	if(strstr(functionname, "art::JniMethodStart"))
    	return JNIMETHOD_START;
  	else if(strstr(functionname, "art::JniMethodEnd"))
    	return JNIMETHOD_END;
  	else if(strstr(functionname, "artFindNativeMethod"))
  		return ART_FIND_NATIVE_METHOD;
  	else
    	return NON_JNIMETHOD;
}


// skip all  and instance fields in a given class
void SkipAllFields(art::ClassDataItemIterator& it)
{
  	while (it.HasNextStaticField()) it.Next();
  	while (it.HasNextInstanceField()) it.Next();
}


void freadProcessing(CPUArchState* env)
{
	size_t size = env->regs[1];
    size_t count = env->regs[2];
    target_ulong fileObj_ptr = env->regs[3];

    if(debuggingOther)
		fprintf(log_others, " read file size: %zu, count: %zu, FILE* %x\n", size, count, fileObj_ptr);
    if(fileObjectPtrs.count(fileObj_ptr) != 0)
    {
    	if(debuggingOther)
    		fprintf(log_others, " read file from fopen\n");
    	setInJson("file_storage", "file read from create");
    }
}


void fgetsProcessing(CPUArchState* env)
{
	size_t size = env->regs[1];
    target_ulong fileObj_ptr = env->regs[2];

    if(debuggingOther)
    	fprintf(log_others, " read file size: %zu, FILE* %x\n", size, fileObj_ptr);
    if(fileObjectPtrs.count(fileObj_ptr) != 0)
    {
    	if(debuggingOther)
    		fprintf(log_others, " fgets file from fopen\n");
    	setInJson("file_storage", "file read from create");
    }

	fgetsRetAdr = env->regs[14];
}



void readProcessing(CPUArchState* env)
{
	int fd = env->regs[0];
    size_t count = env->regs[2];
    if(debuggingOther)
    	fprintf(log_others, " read file fd:%d, count: %zu\n", fd, count);
    if(fileDescriptors.count(fd) != 0)
    {
    	if(debuggingOther)
    		fprintf(log_others, " read file from open\n");
    	setInJson("file_storage", "file read from create");
    }
}



void fopenProcessing(CPUArchState* env)
{
	char file_name[512], mode[5];
    target_ulong name_ptr = env->regs[0];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), name_ptr, file_name, 512);
    target_ulong mode_ptr = env->regs[1];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), mode_ptr, mode, 5);
    
    if(strstr(mode, "a") || strstr(mode, "w"))
    {
		writableFileCreated.insert(file_name);
		// store the return address of 'fopen' then check when pc == retAdr, that's the moment to get return value of 'fopen'
		fopenRetAdr = env->regs[14];
	}

	if(debuggingOther)
		fprintf(log_others, " Opening FILE_NAME - %s, with mode: %s\n", file_name, mode);

	if(strstr(file_name, "/proc") && strstr(file_name, "/status"))
	{
		setInJson("anti-debug", "/proc/pid/status");
	}
}


void openProcessing(CPUArchState* env)
{
	char file_name[512];
	target_ulong name_ptr = env->regs[0];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), name_ptr, file_name, 512);

    int flag = env->regs[1];

    bool created = (flag & O_CREAT);
    if ((flag & O_CREAT) != 0)
    {
    	writableFileCreated.insert(file_name);
    	openRetAdr = env->regs[14];
    }

    if(debuggingOther)
    	fprintf(log_others, " Opening FILE_NAME: %s, with flag: %d, created: %d\n", file_name, flag, created);
}


void closeProcessing(CPUArchState* env)
{
	int fd = env->regs[0];

	fileDescriptors.erase(fd);

	if(debuggingOther)
    	fprintf(log_others, " closing FILE_NAME: %d\n", fd);
}



void unlinkProcessing(CPUArchState* env)
{
	char file_name[512];
	target_ulong name_ptr = env->regs[0];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), name_ptr, file_name, 512);

    if(debuggingOther)
    	fprintf(log_others, " Removing FILE_NAME: %s\n", file_name);
}


void strstrProcessing(CPUArchState* env)
{
	char haystack[512], needle[512];
    target_ulong haystack_ptr = env->regs[0];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), haystack_ptr, haystack, 512);
    target_ulong needle_ptr = env->regs[1];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), needle_ptr, needle, 512);

    if(debuggingOther)
    	fprintf(log_others, " searching within: %s for needle: %s\n", haystack, needle);
    if(debuggingMW)
    	fprintf(log_mw, " searching within: %s for needle: %s\n", haystack, needle);
}


void mmapProcessing(CPUArchState* env)
{
	mmapAdr = env->regs[0];
	size_t len = env->regs[1];
	int prot = env->regs[2];
	int flag = env->regs[3];
	//TODO: wierdest thing ever. Had to switch fd and offset
	int fd = env->regs[5];
	target_ulong offset = env->regs[4];

	if(debuggingOther)
		fprintf(log_others, " mmap addr: 0x%08zx, len: %u, prot: %d, flag: %d, fd: %u, offset: %u\n", mmapAdr, len, prot, flag, fd, offset);


	if(fileDescriptors.count(fd) != 0)
	{
		if(mmapAdr == 0)
		{
			mmapRetAdr = env->regs[14];
		}

		if( ((prot & PROT_WRITE) != 0) && ((prot & PROT_EXEC) != 0) )
		{
			setInJson("code_loading_method", "mmap");

			if(debuggingOther)
				fprintf(log_others, " mmap is mapping fd:%u as w/x\n", fd);
		} 
	}

	// PROT_READ 0x1
    // PROT_WRITE 0x2
    // PROT_EXEC 0x4
    if( (prot & PROT_WRITE) != 0 && debuggingOther)
    	fprintf(log_others, " mmap is mapping fd:%u as writable\n", fd);
    if( (prot & PROT_EXEC) != 0 && debuggingOther)
    	fprintf(log_others, " mmap is mapping fd:%u as executable\n", fd);
}


void mprotectProcessing(CPUArchState* env)
{
	size_t mprotect_addr = env->regs[0];
	size_t len = env->regs[1];
	int prot = env->regs[2];

	if(debuggingOther)
		fprintf(log_others, " mprotect_addr 0x%08zx, len: %zu, prot: %d\n", mprotect_addr, len, prot);

	module* mod = VMI_find_module_by_pc(mprotect_addr, current_cr3, &base);

	if(debuggingOther)
    	fprintf(log_others, " mprotect within module : %s\n", mod->name);

    // PROT_READ 0x1
    // PROT_WRITE 0x2
    // PROT_EXEC 0x4
	if( (prot & PROT_EXEC) != 0 && debuggingOther)
		fprintf(log_others, " mprotect is mapping memory as executable\n");
	if( (prot & PROT_WRITE) != 0 && debuggingOther)
		fprintf(log_others, " mprotect is mapping memory as writable\n");

	if( ((prot & PROT_WRITE) != 0) && ((prot & PROT_EXEC) != 0) && mmapedMemoryRegions.count(mprotect_addr) && debuggingOther)
	{
		setInJson("code_loading_method", "mprotect");
    	fprintf(log_others, "mprotect is mapping mmap addr as wx");
	}
}


void ptraceProcessing(CPUArchState* env)
{
	target_ulong pid = env->regs[1];
	if(!targetPids.count(pid))
	{
		if(debuggingOther)
			fprintf(log_others, "anti-debug to own pid: %u\n", pid);
		setInJson("anti-debug", "pid");
	}
}


void memcmpProcessing(CPUArchState* env)
{
	target_ulong dest_ptr = env->regs[0];
	char src[512];
	target_ulong src_ptr = env->regs[1];
	size_t len = env->regs[2];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), src_ptr, src, 512);
    src[511] = '\0';

    if(debuggingOther)
    	fprintf(log_others, " memcmp_dest 0x%08zx, src: %s, len: %d\n", dest_ptr, src, len);

    module* mod = VMI_find_module_by_pc(dest_ptr, current_cr3, &base);

    if(debuggingOther)
    	fprintf(log_others, " memcmp_dest within module : %s\n", mod->name);
}


void dexFileOpenProcessing(CPUArchState* env)
{
	int fd = env->regs[0];
	char location[512];
	target_ulong loc_ptr = env->regs[1];
	DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), loc_ptr, location, 512);

	if(debuggingOther)
    	fprintf(log_others, "  dexFile open fd: %d, loc: %s\n", fd, location);
}



void findOpenedOatDexProcessing(CPUArchState* env)
{
	char oatlocation[512];
	char dexLocation[512];
	target_ulong oatLoc = env->regs[0];
	target_ulong dexLoc = env->regs[1];

	DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), oatLoc, oatlocation, 512);
	DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), dexLoc, dexLocation, 512);

	if(debuggingOther)
    	fprintf(log_others, "  find opened oat:%s, dex: %s\n", oatlocation, dexLocation);
}


void vsnprintfProcessing(CPUArchState* env)
{
	char formatStr[512];
	target_ulong buf_ptr = env->regs[0];
	target_ulong str_ptr = env->regs[1];
	DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), str_ptr, formatStr, 512);

	if(debuggingOther)
    	fprintf(log_others, "  vsnprint buffer: 0x%x, format String: %s\n", buf_ptr, formatStr);
}



void memchrProcessing(CPUArchState* env)
{
	target_ulong buf_ptr = env->regs[0];
	size_t ch = env->regs[1];
	size_t len = env->regs[2];

	if(debuggingOther)
    	fprintf(log_others, "  memchr buffer: 0x%x, searching for char: %c, in first %u chars\n", buf_ptr, ch, len);
}


void writeProcessing(CPUArchState* env)
{
	int fd = env->regs[0];
	target_ulong buf_ptr = env->regs[1];
	module* mod = VMI_find_module_by_pc(buf_ptr, current_cr3, &base);

	if(debuggingOther)
	{
		fprintf(log_others, "  write to fd: %d\n", fd);
    	fprintf(log_others, " write buffer in module : %s\n", mod->name);
	}
}


#endif

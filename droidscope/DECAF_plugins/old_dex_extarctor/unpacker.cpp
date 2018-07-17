
/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
* @author Abhishek VB
* @date June 22 2015
*/
#include "unpacker.h"

template <class Container>
void binary_save(Container&& data, std::string const& bin_file_name)
{
    std::ofstream out(bin_file_name, std::ios::out | std::ios::app | std::ios::binary);
    if (!out) 
    {
      throw std::runtime_error("Could not open \"" + bin_file_name + "\" for writing");
    }
    std::copy(data.begin(), data.end(), std::ostream_iterator<std::uint8_t>(out, ""));  // PON 3
}



static void extract_art_offsets_from_module(target_ulong base,
                                          module* dirty_module,
                                          CPUArchState* env,
                                          target_ulong cr3,
                                          std::string moduleName) 
{
  // if already done, return
  if (base_to_offsets.count(base) ) { //|| (moduleName.find(".apk") != std::string::npos)) {
    return;
  }

  std::string error_msg;
  std::unique_ptr<art::OatFile> oat_file(art::OatFile::Open(moduleName, moduleName, nullptr, false, &error_msg));
  // CHECK(oat_file.get() != NULL) << calc_dump << ": " << error_msg;

  if (oat_file.get() == nullptr) 
  {
    std::cout << moduleName << ": " << error_msg;
    return;
  }

  DECAF_printf("art_file_done__! %s\n", moduleName.c_str());

  // std::unordered_map<target_ulong, std::string> to_add_offsets;
  // std::unordered_map<uint32_t, art::DexFile *> to_add_dex_files;

  const std::vector<const art::OatFile::OatDexFile*> oat_dex_files = oat_file->GetOatDexFiles();


  // for every dex file within the oat file, we open the dex and get all the classes within that dex file
  // And for all the classes, we skip the fields, extract method information and 
  for (size_t i = 0; i < oat_dex_files.size(); i++) {
    const art::OatFile::OatDexFile* oat_dex_file = oat_dex_files[i];
    CHECK(oat_dex_file != nullptr);
    std::string error_msg;

    const art::DexFile* dex_file = oat_dex_file->OpenDexFile(&error_msg);
    // std::unique_ptr<const art::DexFile> dex_file(
    //    oat_dex_file->OpenDexFile(&error_msg));

    if (dex_file == nullptr) {
      std::cout << "Failed to open dex file '"
                << oat_dex_file->GetDexFileLocation() << "': " << error_msg;
      continue;
    }
    else
    {
      std::cout << "Open dex file: "<< oat_dex_file->GetDexFileLocation() << std::endl;
    }

    size_t numOfClass = dex_file->NumClassDefs();
    for (size_t class_def_index = 0; class_def_index < numOfClass; ++class_def_index) 
    {
      const art::DexFile::ClassDef& class_def = dex_file->GetClassDef(class_def_index);
      const art::OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
      const byte* class_data = dex_file->GetClassData(class_def);
      
      if (class_data != nullptr) 
      {
        art::ClassDataItemIterator it(*dex_file, class_data);
        SkipAllFields(it);
        uint32_t class_method_index = 0;
        while (it.HasNextDirectMethod()) 
        {
          const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index++);
          uint32_t code_offset = oat_method.GetCodeOffset();
          framework_offsets[code_offset] = PrettyMethod(it.GetMemberIndex(), *dex_file, true);
          framework_sizes[code_offset] = oat_method.GetQuickCodeSize();
          it.Next();
        }

        while (it.HasNextVirtualMethod()) 
        {
          const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index++);
          uint32_t code_offset = oat_method.GetCodeOffset();
          framework_offsets[code_offset] = PrettyMethod(it.GetMemberIndex(), *dex_file, true);
          framework_sizes[code_offset] = oat_method.GetQuickCodeSize();
          it.Next();
        }
      }//end if (class_data != nullptr)
    }//for all classes
  }//for all OatDexFile

  base_to_oat_file[base] = (void*)oat_file.release();
}


static void dumpModule(target_ulong base_, target_ulong size, std::string moduleName, CPUArchState* env, target_ulong cr3)
{
  std::vector<uint8_t> module_contents;

  target_ulong module_end = base_ + size;

  for (target_ulong module_base = base_; module_base != module_end; module_base += 1) {

    uint8_t ph = 0;
    DECAF_read_mem_with_pgd(env, cr3, module_base, (void*)&ph,
                            sizeof(uint8_t));

    module_contents.push_back(ph);
  }

  std::string name1 = dumps_dir + "libc" + std::to_string(current_module_file) + ".so";

  std::string calc_dump = name1;

  binary_save(module_contents, calc_dump);

  current_module_file++;
}


// For all other oat files that we have to calculte from base + size
static void extract_art_offsets__(target_ulong base_, target_ulong size, std::string moduleName, 
                                  CPUArchState* env, target_ulong cr3, bool forceExtract)
{
  if( (base_to_offsets.count(base_)) || (bad_dex_file_bases[base_] > 3)) // || (moduleName.find(".apk") != std::string::npos)) {
  {
    if(!forceExtract)
      return;
  }

  printf("module: %s, base: 0x%x, size: 0x%x\n", moduleName.c_str(), base_, size);

  // Try to grab the memory and open an OAT file
  std::vector<uint8_t> oat_file_contents;

  target_ulong oat_file_end = base_ + size;

  for (target_ulong oat_file_base = base_; oat_file_base != oat_file_end;
       oat_file_base += 1) {
    // hwaddr phys_ = cpu_get_phys_page_debug(env, oat_file_base);

    // void *phys_buf_ = NULL;

    uint8_t ph = 0;

    DECAF_read_mem_with_pgd(env, cr3, oat_file_base, (void*)&ph,
                            sizeof(uint8_t));

    oat_file_contents.push_back(ph);
  }

  std::string name1 = dumps_dir + std::to_string(current_dex_file) + ".oat";
  //  FILE *dumped = fopen(name1.c_str(), "w+");
  //  fclose(dumped);
  /*
    std::vector<uint8_t> elf_magic_needle{ 'E', 'L', 'F', '\0' };
    std::vector<uint8_t>::iterator itt =
        std::search(oat_file_contents.begin(), oat_file_contents.end(),
                    elf_magic_needle.begin(), elf_magic_needle.end());
    if(itt != oat_file_contents.end())
    {
          oat_file_contents.erase(oat_file_contents.begin(), itt);
    }
    else {
      return;
    }
    */

  std::string calc_dump = name1;

  binary_save(oat_file_contents, calc_dump);

  ++current_dex_file;
  std::vector<uint8_t> oat_magic_needle{'o', 'a', 't', '\n',
                                        '0', '3', '9', '\0'};
  std::vector<uint8_t>::iterator it = std::search(oat_file_contents.begin(), oat_file_contents.end(),
                  oat_magic_needle.begin(), oat_magic_needle.end());

  oat_file_contents.erase(oat_file_contents.begin(), it);

  std::vector<uint8_t>::iterator it1 = std::search(oat_file_contents.begin(), oat_file_contents.end(),
                  oat_magic_needle.begin(), oat_magic_needle.end());

  if (it1 != oat_file_contents.end()) 
  {
    oat_file_contents.erase(oat_file_contents.begin(), it1);
  }

  std::string error_msg;
  std::unique_ptr<art::OatFile> oat_file(art::OatFile::OpenMemory(oat_file_contents, calc_dump, &error_msg));
  CHECK(oat_file.get() != NULL) << calc_dump << ": " << error_msg;

  if (oat_file.get() == nullptr) 
  {
    if (bad_dex_file_bases.count(base_))
      bad_dex_file_bases[base_]++;
    else
      bad_dex_file_bases[base_] = 1;

    setInJson("dex_file_integrity", "false");
    return;
  }

  DECAF_printf("art_file_done__!! %s %s\n", moduleName.c_str(), name1.c_str());
  oatDumped = true;


  DECAF_printf("modifying libc.so \n");
  DECAF_printf("modifying libc.so \n");
  DECAF_printf("modifying libc.so \n");

  std::unordered_map<target_ulong, std::string> to_add_offsets;
  std::unordered_map<target_ulong, target_ulong> to_add_sizes;
  const std::vector<const art::OatFile::OatDexFile*> oat_dex_files_ =
      oat_file->GetOatDexFiles();

  for (size_t i = 0; i < oat_dex_files_.size(); i++) {
    const art::OatFile::OatDexFile* oat_dex_file = oat_dex_files_[i];
    CHECK(oat_dex_file != nullptr);
    std::string error_msg;

    const art::DexFile* dex_file = oat_dex_file->OpenDexFile(&error_msg);
    std:string dex_loc = oat_dex_file->GetDexFileLocation();

    if (dex_file == nullptr) {
      std::cout << "Failed to open dex file '" << dex_loc << "': " << error_msg;
      continue;
    }
    else
    {
      if(debuggingOther)
        fprintf(log_others, "open dex file: %s\n", dex_loc.c_str());
      std::cout << "Open dex file: "<< dex_loc << std::endl;
    }

    if(dumpCode)
    {
      for (size_t class_def_index = 0; class_def_index < dex_file->NumClassDefs(); class_def_index++) 
      {
        const art::DexFile::ClassDef& class_def = dex_file->GetClassDef(class_def_index);
        const art::OatFile::OatClass oat_class = oat_dex_file->GetOatClass(class_def_index);
        const byte* class_data = dex_file->GetClassData(class_def);
        if (class_data != nullptr)
        {
          art::ClassDataItemIterator it(*dex_file, class_data);
          SkipAllFields(it);
          uint32_t class_method_index = 0;
          while (it.HasNextDirectMethod()) 
          {
            const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index++);
            uint32_t code_offset = oat_method.GetCodeOffset();
            if(debuggingOther)
            {
              fprintf(log_others, "module %s --- has function direct: %s -- has code offset: 0x%x, member index: 0x%x\n", 
                moduleName.c_str(), (PrettyMethod(it.GetMemberIndex(), *dex_file, true)).c_str(), code_offset, it.GetMemberIndex());
            }
            to_add_offsets[code_offset] = PrettyMethod(it.GetMemberIndex(), *dex_file, true);
            to_add_sizes[code_offset] = oat_method.GetQuickCodeSize();
            it.Next();
          }
          while (it.HasNextVirtualMethod()) 
          {
            const art::OatFile::OatMethod oat_method = oat_class.GetOatMethod(class_method_index++);
            uint32_t code_offset = oat_method.GetCodeOffset();

            if(debuggingOther)
            {
              fprintf(log_others, "module %s --- has function virtual: %s -- has code offset: 0x%x, member index: 0x%x\n", 
                moduleName.c_str(), (PrettyMethod(it.GetMemberIndex(), *dex_file, true)).c_str(), code_offset, it.GetMemberIndex());
            }

            to_add_offsets[code_offset] =  PrettyMethod(it.GetMemberIndex(), *dex_file, true);
            to_add_sizes[code_offset] = oat_method.GetQuickCodeSize();
            it.Next();
          }

        }//end if (class_data != nullptr)
      }//end for every class within dex file
    }

  }//end for every dex file

  base_to_sizes[base] = std::move(to_add_sizes);
  base_to_offsets[base] = std::move(to_add_offsets);
  base_to_oat_file[base] = (void*)oat_file.release();
}


// Given an ArtMethod pointer, extract Dex file pointer based on data structural information
static art::DexFile* extractDexFile(CPUArchState* env, target_ulong dex_cache, target_ulong declaring_class, 
    art::mirror::ArtMethod* methodzz, target_ulong cr3)
{
  // Get the ArtMethod's declaring class
  art::MemberOffset declaring_class_offset = methodzz->DeclaringClassOffset();
  byte* raw_addr = reinterpret_cast<byte*>(methodzz) + declaring_class_offset.Int32Value();
  art::mirror::HeapReference<art::mirror::Class>* objref_addr = 
    reinterpret_cast<art::mirror::HeapReference<art::mirror::Class>*>(raw_addr);
  declaring_class = (target_ulong)objref_addr->AsVRegValue();

  art::mirror::Class* clazz = nullptr;
  char block2[sizeof(art::mirror::Class)];
  DECAF_read_mem_with_pgd(env, pgd_strip(cr3), declaring_class, block2, sizeof(art::mirror::Class));
  clazz = (art::mirror::Class*)block2;

  // Get the Declaring class's DexCache
  art::MemberOffset dex_cache_offset = clazz->DexCacheOffset();
  raw_addr = reinterpret_cast<byte*>(clazz) + dex_cache_offset.Int32Value();
  art::mirror::HeapReference<art::mirror::DexCache>* dexcache_objref_addr = 
    reinterpret_cast<art::mirror::HeapReference<art::mirror::DexCache>*>(raw_addr);
  dex_cache = (target_ulong)dexcache_objref_addr->AsVRegValue();

  art::mirror::DexCache* dexcachezz = nullptr;
  char block3[sizeof(art::mirror::DexCache)];
  DECAF_read_mem_with_pgd(env, pgd_strip(cr3), dex_cache, block3, sizeof(art::mirror::DexCache));
  dexcachezz = (art::mirror::DexCache*)block3;

  // Get the DexFile from the DexCache of the declaring class of the Artmethod
  art::MemberOffset dex_file_offset = dexcachezz->GetDexFileOffset();
  raw_addr = reinterpret_cast<byte*>(dexcachezz) + dex_file_offset.Int32Value();
  uint64_t* dex_file_ref = reinterpret_cast<uint64_t*>(raw_addr);

  art::DexFile* dexfilezz = nullptr;
  char block4[sizeof(art::DexFile)];
  DECAF_read_mem_with_pgd(env, pgd_strip(cr3), *dex_file_ref, block4, sizeof(art::DexFile));
  dexfilezz = (art::DexFile*)block4;

  return dexfilezz;
}


// static void handle_instruction(Dalvik_VMI_Callback_Params* params)
// {
//   CPUARMState *env = params->ib.env;
//   target_ulong cr3 = DECAF_getPGD(env);

//   if (!(targetcr3s.count(cr3)))
//     return;

//   char ins[512];
//   //disas_dalvik_ins(env, (uint16_t *)&(params->ib.insn), params->ib.dalvik_file_base, ins);
//   fprintf(log_others, "Executing dalvik_insn at - 0x%x\n", params->ib.dalvik_pc);
// }



// module_load cb
static void module_load_cb(VMI_Callback_Params* params) {
  target_ulong module_base, module_end, cr3 = params->lm.cr3;

  if (!(targetcr3s.count(cr3)))
    return;

  module_base = params->lm.base;
  module_end = params->lm.size + module_base;

  if(getValFromJson("packer") == "")
  {
    std::string packer = "";
    if (strstr(params->lm.name, "libprotect") != NULL || strstr(params->lm.name, "libjiagu") != NULL)
      packer = "qihoo";
    else if (strstr(params->lm.name, "libdemolish") != NULL || strstr(params->lm.name, "libmobisec") != NULL)
      packer = "ali";
    else if (strstr(params->lm.name, "baidu") != NULL)
      packer = "baidu";
    else if (strstr(params->lm.name, "libsec") != NULL || strstr(params->lm.name, "libSecShell") != NULL)
      packer = "bangcle";
    else if (strstr(params->lm.name, "libexec") != NULL)
      packer = "ijiami";
    else if (strstr(params->lm.name, "libshell") != NULL || strstr(params->lm.name, "libBugly") != NULL)
      packer = "tencent";
    setInJson("packer", packer);
  }
  
  if(debuggingModule)
  {
    fprintf(log_modules, "cr3: %x, module loaded - %s module_base 0x%x module_end 0x%x, size 0x%x\n", 
      cr3, params->lm.name, module_base, module_end, (module_end - module_base));
  }

  if(debuggingOther)
    fprintf(log_others, "cr3: %x, module loaded - %s module_base 0x%x module_end 0x%x, size 0x%x\n", 
      cr3, params->lm.name, module_base, module_end, (module_end - module_base));

  
  map<target_ulong, uint8_t>::iterator end = byte_addrs_written[cr3].end();
  vector<map<target_ulong, uint8_t>::iterator> toDelete;

  for(map<target_ulong, uint8_t>::iterator it = byte_addrs_written[cr3].begin(); it != end; it++)
  {
    if(it->first >= module_base && it->first <= module_end) 
      //byte_addrs_written[cr3].erase(it);
      toDelete.push_back(it);
  }

  for(int i = 0; i < toDelete.size(); i++)
    byte_addrs_written[cr3].erase(toDelete[i]);
}


// mem_write_cb
static void hook_writes(DECAF_Callback_Params* params) {
  if (!(targetcr3s.count(current_cr3)))
    return;
  
  /*
   * main idea here is to set value to 1 if addr is already in pcSet
   * addr already exists in pcSet' means that the address written has been executed
   */
  target_ulong addr = params->mw.vaddr;
  int inPCset = 0;
  if(pcSet.count(current_cr3)) {
    inPCset = pcSet[current_cr3].count(addr);
  }

  if(inPCset) {
    (byte_addrs_written[current_cr3])[addr] = 1;
  }
  else {
    (byte_addrs_written[current_cr3])[addr] = 0;
  }

  byte_addrs_written_inc[current_cr3].insert(addr);

  if(debuggingMW)
  {
    fprintf(log_mw, "cr3: 0x%08x, virt_addr 0x%08x phys_addr 0x%08x value %u\n", 
      current_cr3, params->mw.vaddr, params->mw.paddr, params->mw.value);

    // module* mod = VMI_find_module_by_pc(params->mw.vaddr, current_cr3, &base);
    // fprintf(log_mw, "writing to module: %s\n", mod->name);
  }
}


static void block_begin_cb(DECAF_Callback_Params* param)
{
  char modname[1024];
  char functionname[1024];

  CPUArchState* env = param->bb.env;

  target_ulong cur_pc = param->bb.cur_pc;
  target_ulong cr3 = DECAF_getPGD(env);
  
  if (DECAF_is_in_kernel(env) || !(targetcr3s.count(cr3)))
  {
    current_cr3 = 0x00;
    return;
  }

  current_env = param->bb.env;
  current_cr3 = cr3;
  module* art_module = NULL;
  art_module = VMI_find_module_by_pc(cur_pc, cr3, &base);

  // exclude Webview module
  if(art_module != NULL && strstr(art_module->name, "libwebviewchromium.so"))
    return;

  if(dumpLibc && art_module != NULL && strstr(art_module->name, "libc") && !libcDumped) {
    dumpModule(base, art_module->size, std::string(art_module->name), env, cr3);
    libcDumped = true;
  }


  ////////////////////////////////////////////////////////////////////////////////////////
  /*
    added for self-modifying and incremental-unpacking
    self-modifying: if an address x was executed (in psSet) and written after execution (in byte_addrs_written, value = 1)
                  and then gets executed again
    incremental-unpacking: if there are two or more waves of writing, we consider it as incremental unpacking
  */
  //pcSet.insert(cur_pc);
  pcSet[current_cr3].insert(cur_pc);
  if(debuggingMW)
    fprintf(log_mw, "current_cr3: 0x%x, executing: 0x%x\n", current_cr3, cur_pc);


  if(byte_addrs_written.count(current_cr3) && byte_addrs_written[current_cr3].count(cur_pc))
  {
    if((byte_addrs_written[current_cr3])[cur_pc] == 1)
    {
      setInJson("self_modifying", "true");
      if(libcDumped)
        libcDumped = false;
      if(debuggingOther)
        fprintf(log_others, "self_modified module: %s\n", art_module->name);

      // int ret = funcmap_get_name_c(cur_pc, DECAF_getPGD(env), modname, functionname);
      // if(ret == 0 && debuggingFunctions)
      // {
      //   fprintf(log_functions, "self_modifiedpc: %x\n", cur_pc);
      //   fprintf(log_functions, "cr3: %x, module name: %s, function name: %s\n", cr3, modname, functionname);
      // }

      if(debuggingMW) {
        fprintf(log_mw, "current_cr3: 0x%x, self_modified address: 0x%x\n", current_cr3, cur_pc);
        fprintf(log_mw, "module: %s\n", art_module->name);
      }


      if (art_module != NULL && strstr(art_module->name, "framework") == NULL
          && (strstr(art_module->name, "oat") != NULL  
              || strstr(art_module->name, "dex") != NULL 
              || strstr(art_module->name, "apk") != NULL)) {
        if(debuggingOther) {
          fprintf(log_others, "self_modifying_in_dex: %s\n", art_module->name);
          fprintf(log_others, "current_cr3: 0x%x, executing: 0x%x\n", current_cr3, cur_pc);
          self_modifying_addrs.insert(cur_pc);
        }
        setInJson("self_modifying_in_dex", art_module->name);
      }
    }
  }

  if(byte_addrs_written_inc.count(current_cr3) && byte_addrs_written_inc[current_cr3].count(cur_pc))
  {
    setInJson("packed", "true");
    wave++;
    byte_addrs_written_inc[current_cr3].clear();
    increment_something("wave");
    if(wave > 1)
    {
      setInJson("incremental_unpacking", "true");
    }
  }
  ////////////////////////////////////////////////////////////////////////////////////////


  // check if current pc  == fopenRetAdr
  // If yes, it means 'fopen' has returned, we extract the return value
  if(openRetAdr != 0 && openRetAdr == cur_pc)
  {
    fileDescriptors.insert(env->regs[0]);
    if(debuggingOther)
      fprintf(log_others, "file descriptor returned : %d\n", env->regs[0]);
    openRetAdr = 0;
  }

  if(mmapRetAdr != 0 && mmapRetAdr == cur_pc)
  {
    target_ulong addr = env->regs[0];
    mmapedMemoryRegions.insert(addr);
    if(debuggingOther)
      fprintf(log_others, "mmap memory region returned : 0x%8x\n", addr);
    mmapRetAdr = 0;
  }

  if(fopenRetAdr != 0 && fopenRetAdr == cur_pc)
  {
    target_ulong fileObj_ptr = env->regs[0];
    if(debuggingOther)
      fprintf(log_others, "FILE pointer returned : 0x%x\n", env->regs[0]);
    fopenRetAdr = 0;

    fileObjectPtrs.insert(fileObj_ptr);
  }

  if(fgetsRetAdr != 0 && fgetsRetAdr == cur_pc)
  {
    char content[512];
    target_ulong char_ptr = env->regs[0];
    DECAF_read_mem_with_pgd(env, pgd_strip(current_cr3), char_ptr, content, 512);

    if(debuggingOther)
      fprintf(log_others, "file content read : %s\n", content);

    fgetsRetAdr = 0;
  }

  
  // extract method info from framework
  if(art_module != NULL && (strstr(art_module->name, "system@framework@boot.oat") != NULL)) 
  {
    if(!framework_offsets_extracted) 
    {
      char* oat_file_str;
      extract_oat_file(env, base, &oat_file_str);
      extract_art_offsets_from_module(base, art_module, env, cr3,
                                    std::string(oat_file_str));
      framework_offsets_extracted = true;
    }


    if(PRINT_FRAMEWORK_CALL)
    {
      if(framework_offsets.count(cur_pc - base - 0x1000))
      {
        std::string framworkCall = framework_offsets[(cur_pc - base - 0x1000)];
        //std::cout<< "cr3: " << cr3 << "\n\tAPI call = " << framworkCall.c_str()<< std::endl;
        if(withinJNICall == true)
        {
          setInJson("jni_hiding", "true");
          if(debuggingOther)
            fprintf(log_others, "cr3: %x, module: framework, function call = %s \n", cr3, framworkCall.c_str());
        }
        else
        {
          if(debuggingOther)
            fprintf(log_others, "cr3: %x, module: framework, function call = %s \n", cr3, framworkCall.c_str());
        }

        if(framworkCall.find("boolean android.os.Debug.isDebuggerConnected()") != std::string::npos)
          setInJson("anti-debug", "isDebuggerConnected");
      }
    }
  }

  // Yue: dump the functions called in libc module
  if(art_module != NULL
    && (strstr(art_module->name, "libc") || strstr(art_module->name, "libart")))
  {
      int ret = funcmap_get_name_c(cur_pc, DECAF_getPGD(env), modname, functionname);
      if(ret == 0)
      {
        // if(debuggingOther)
        //   fprintf(log_others, "cr3: %x, module name: %s, function name: %s\n", cr3, modname, functionname);

        if(strncmp(functionname, "fread", 5) == 0 && strlen(functionname) == 5)
        {
          freadProcessing(env);
        }
        else if(strncmp(functionname, "read", 4) == 0 && strlen(functionname) == 4)
        {
          readProcessing(env);
        }
        else if(strncmp(functionname, "fgets", 5) == 0 && strlen(functionname) == 5)
        {
          fgetsProcessing(env);
        }
        else if(strncmp(functionname, "fopen", 5) == 0 && strlen(functionname) == 5)
        {
          fopenProcessing(env);
        }
        else if(strncmp(functionname, "open", 4) == 0 && strlen(functionname) == 4)
        {
          openProcessing(env);
        }
        else if(strncmp(functionname, "mmap", 4) == 0 && strlen(functionname) == 4)
        {
          mmapProcessing(env);
        }
        else if(strncmp(functionname, "mprotect", 8) == 0 && strlen(functionname) == 8)
        {
          mprotectProcessing(env);
        }
        else if(strncmp(functionname, "ptrace", 5) == 0 && strlen(functionname) == 5)
        {
          ptraceProcessing(env);
        }
        else if(strncmp(functionname, "strstr", 6) == 0 && strlen(functionname) == 6)
        {
          strstrProcessing(env);
        }

        // else if(strncmp(functionname, "memcmp", 6) == 0 && strlen(functionname) == 6)
        // {
        //   memcmpProcessing(env);
        // }
        // else if(strncmp(functionname, "unlink", 6) == 0 && strlen(functionname) == 6)
        // {
        //   unlinkProcessing(env);
        // }
        else if(strstr(functionname, "art::DexFile::OpenFile") != NULL)
        {
          dexFileOpenProcessing(env);
        }
        else if(strstr(functionname, "art::ClassLinker::FindOpenedOatDexFile") != NULL)
        {
          findOpenedOatDexProcessing(env);
        }
        // else if(strstr(functionname, "vsnprintf") != NULL)
        // {
        //   vsnprintfProcessing(env);
        // }
        // else if(strncmp(functionname, "memchr", 6) == 0 && strlen(functionname) == 6)
        // {
        //   memchrProcessing(env);
        // }
        else if(strncmp(functionname, "write", 5) == 0 && strlen(functionname) == 5)
        {
          writeProcessing(env);
        }
      }
  }

  if(art_module != NULL && strstr(art_module->name, "libart"))
  {
    if(funcmap_get_name_c(cur_pc, DECAF_getPGD(env), modname, functionname) == 0) 
    {
      // keep track of JniMethodStart* and JniMethodEnd* pair
      int ret_jni = isJniMethodFunc(functionname);
      if(ret_jni == JNIMETHOD_START)
      {
        jniMethodDepth++;
        if(lastCallNativeInApk)
        {
          withinJNICall = true;
          jniDepthForJniCall = jniMethodDepth;
          if(debuggingOther)
            fprintf(log_others, "cr3: %x, jni call begins\n", cr3);
        }
      }
      else if(ret_jni == JNIMETHOD_END && jniMethodDepth > 0)
      {
        if(withinJNICall == true && jniDepthForJniCall == jniMethodDepth)
        {
          withinJNICall = false;
          if(debuggingOther)
            fprintf(log_others, "cr3: %x, jni call ends\n", cr3);
        }
        jniMethodDepth--;
      }
      else if(ret_jni == ART_FIND_NATIVE_METHOD && withinJNICall == false)
      {
        withinJNICall = true;
        jniDepthForJniCall = jniMethodDepth;
        if(debuggingOther)
          fprintf(log_others, "cr3: %x, jni call begins\n", cr3);
      }

      int reg_num = is_an_invoke_call(functionname);
      if (reg_num != NON_INVOKE_CALL)
      {
        // this pointer points to artMethod object
        target_ulong dex_cache, declaring_class, called_art_method = env->regs[0];

        // Get the ArtMethod
        art::mirror::ArtMethod* methodzz;
        char block1[sizeof(art::mirror::ArtMethod)];
        DECAF_read_mem_with_pgd(env, pgd_strip(cr3), called_art_method, block1, sizeof(art::mirror::ArtMethod));
        methodzz = (art::mirror::ArtMethod*)(block1);

        art::DexFile* dexfilezz = extractDexFile(env, dex_cache, declaring_class, methodzz, cr3);

        /**********************************************************************/
        /* WE ARE DONE! WE GOT THE DEXFILE! NOW TIME TO GET THE FUNCTION NAME */
        /**********************************************************************/
        // Try to grab all methods from the dex file!
        // This process is simialar to what is done in the DexMethodIterator
        byte* raw_addr = reinterpret_cast<byte*>(dexfilezz) + 4;
        uint32_t* begin_decaf = reinterpret_cast<uint32_t*>(raw_addr);
        target_ulong dex_begin = (target_ulong)(uintptr_t)(*begin_decaf);
        
        module* dirty_module = VMI_find_module_by_pc(reinterpret_cast<target_ulong>(*begin_decaf), cr3, &base);

        if(debuggingOther)
        {
          fprintf(log_others, "cr3: %x, called_art_method: %x\n", cr3, called_art_method);
          fprintf(log_others, "cr3: 0x%x, dex_begin: 0x%x\n", cr3, dex_begin);
          fprintf(log_others, "dirty_module: %s\n", dirty_module->name);
        }
        
        if (dirty_module != NULL 
          && (strstr(dirty_module->name, "oat") != NULL || strstr(dirty_module->name, "dex") != NULL || strstr(dirty_module->name, "dalvik") != NULL)
          && strstr(dirty_module->name, "framework") == NULL)
        {
          if(debuggingOther)
            fprintf(log_others, "dirty_module name: %s, base: 0x%x, size: 0x%x\n", dirty_module->name, base, dirty_module->size);
          extract_art_offsets__(base, dirty_module->size, std::string(dirty_module->name), env, cr3, false);
        }
        // else if (dirty_module == NULL)
        // {
        //   target_ulong prev_end = 0x00;
        //   dirty_module = VMI_find_next_module(reinterpret_cast<target_ulong>(*begin_decaf), cr3, &base, &prev_end);
          
        //   if (dirty_module != NULL 
        //     && (strstr(dirty_module->name, "oat") != NULL || strstr(dirty_module->name, "dex") != NULL)
        //     && strstr(dirty_module->name, "framework") == NULL)
        //   {
        //     extract_art_offsets__(prev_end, base - prev_end, std::string(dirty_module->name), env, cr3, false);
        //   }
        // }

        if(dirty_module == NULL)
          return;

        if (dirty_module && strstr(dirty_module->name, "framework") != NULL)
          return;

        /*  Here we try to replicate the process used in
         * DexFile->GetMethodName(MethodId&)
         *  The process goes something like this
         *  -> From MethodId get the offset of the name of method in the
         * StringIds
         *  -> Extract the exact StringId from this offset
         *  -> Use this StringId to find the offset of the actual string
         *      in the DexFile from the base of the dexfile
         *
        */
        // this is to extract method name
        raw_addr = reinterpret_cast<byte*>(dexfilezz) + 8;
        uint32_t* dex_file_size = reinterpret_cast<uint32_t*>(raw_addr);        

        // extract code item offset
        art::MemberOffset dex_code_item_offset = methodzz->GetDexCodeItemOffset();
        raw_addr = reinterpret_cast<byte*>(methodzz) + dex_code_item_offset.Int32Value();
        uint32_t* code_item_offset = reinterpret_cast<uint32_t*>(raw_addr);

        // extract the offset of the method in the MethodIds array
        art::MemberOffset dex_method_id_offset = methodzz->GetDexMethodIndexOffset();
        raw_addr = reinterpret_cast<byte*>(methodzz) + dex_method_id_offset.Int32Value();
        uint32_t* dex_method_id = reinterpret_cast<uint32_t*>(raw_addr);

        if(debuggingOther)
        {
          fprintf(log_others, "dex_file_size: 0x%x\n", *dex_file_size);
          fprintf(log_others, "code_item_offset: 0x%x\n", *code_item_offset);
          fprintf(log_others, "dex_method_id: 0x%x\n", *dex_method_id);
        }

        // get the base of the MethodIds array and add the offset to get the appropriate MethodId member
        //art::MemberOffset dexfile_method_ids_offset = dexfilezz->GetMethodIdsOffset();
        raw_addr = reinterpret_cast<byte*>(dexfilezz) + 48;
        uint32_t* ids_decaf = reinterpret_cast<uint32_t*>(raw_addr);
        art::DexFile::MethodId* temp_id = (art::DexFile::MethodId*)(*ids_decaf);
        temp_id = temp_id + *dex_method_id;

        art::DexFile::MethodId* idzz;
        char block5[sizeof(art::DexFile::MethodId)];
        DECAF_read_mem_with_pgd(env, pgd_strip(cr3), (target_ulong)(uintptr_t)temp_id, block5, sizeof(art::DexFile::MethodId));
        idzz = (art::DexFile::MethodId*)block5;

        // Now we have the MethodId in `idzz`, and idzz->name_idx_ holds the offset of the StringId
        // Proceed getting the StringId
        raw_addr = reinterpret_cast<byte*>(dexfilezz) + 48 - 12;
        uint32_t* str_ids_decaf = reinterpret_cast<uint32_t*>(raw_addr);
        art::DexFile::StringId* temp_str_id = (art::DexFile::StringId*)(*str_ids_decaf);
        temp_str_id = temp_str_id + idzz->name_idx_;

        art::DexFile::StringId* str_idzz;
        char block6[sizeof(art::DexFile::StringId)];
        DECAF_read_mem_with_pgd(env, pgd_strip(cr3), (target_ulong)(uintptr_t)temp_str_id, block6, sizeof(art::DexFile::StringId));
        str_idzz = (art::DexFile::StringId*)block6;
        // We now have the StringId at str_idzz, PHEW!!
        char block7[200];
        DECAF_read_mem_with_pgd(env, pgd_strip(cr3), dex_begin + str_idzz->string_data_off_ + 1, block7, 200);
        block7[199] = '\0';
        if(reg_num == ARTMETHOD_INVOKE)
        {
          if(debuggingFunctions)
            fprintf(log_functions, "Invoke java function call = %s\n", block7);
          if(debuggingOther)
            fprintf(log_others, "Invoke java function call = %s\n", block7);
          // if(strstr(block7, "onCreate") != NULL)
          //   extract_art_offsets__(base, dirty_module->size, std::string(dirty_module->name), env, cr3, true);
        }
        else if (reg_num == INTERPRETER_DOCALL) 
        {
          increment_something("num_dalvik_methods");

          if(debuggingFunctions)
            fprintf(log_functions, "DoCall java function call = %s\n", block7);
          if(debuggingOther)
            fprintf(log_others, "DoCall java function call = %s\n", block7);

          art::DexFile::CodeItem* this_code_item;
          char code_item_block[sizeof(art::DexFile::CodeItem)];
          DECAF_read_mem_with_pgd(env, pgd_strip(cr3),
                                  dex_begin + (target_ulong)(*code_item_offset),
                                  code_item_block,
                                  sizeof(art::DexFile::CodeItem));
          this_code_item = (art::DexFile::CodeItem*)code_item_block;

          uint32_t num_bytes_to_read = this_code_item->insns_size_in_code_units_ * 2;

          target_ulong to_check_start = dex_begin + (target_ulong)(*code_item_offset);
          target_ulong to_check_end = to_check_start + sizeof(art::DexFile::CodeItem) + num_bytes_to_read + 4;

          if(debuggingFunctions) {
            fprintf(log_functions, "sizeof:  0x%x, num_byptes: 0x%x\n", sizeof(art::DexFile::CodeItem), num_bytes_to_read);
            fprintf(log_functions, " start: 0x%x, end: 0x%x\n", to_check_start, to_check_end);
          }


          while (to_check_end != to_check_start)
          {
            // if (byte_addrs_written[cr3].count(to_check_start))
            // {
            //   increment_something("num_dirty_dalvik_methods");
            //   setInJson("dirty_dalvik_code", "true");
            //   break;
            // }
            if(self_modifying_addrs.empty())
              break;
            if(self_modifying_addrs.count(to_check_start)) {
              if(debuggingFunctions)
                fprintf(log_functions, "self self-modifying happens in :%s\n", block7);
            }
            ++to_check_start;
          }



          if(debuggingFunctions)
            fflush(log_functions);
        }// end DoCall case
      }// end if (reg_num != NONINVOKE_CALL)
    }
  }// end if (libart)
  lastCallNativeInApk = false;

// check if base_to_offsets contains the current base, if yes that means the app maybe calling a native function
end:
  if(base_to_offsets.count(base))
  {
    std::unordered_map<target_ulong, std::string>& oat_module_offsets = base_to_offsets[base];
    std::unordered_map<target_ulong, target_ulong>& oat_module_sizes = base_to_sizes[base];

    if(oat_module_offsets.count((cur_pc - base - 0x1000)))
    {
      if(art_module != NULL && strstr(art_module->name, "apk"))
        lastCallNativeInApk = true;

      increment_something("num_native_methods");

      std::string funcName = oat_module_offsets[(cur_pc - base - 0x1000)];
      //TODO
      if(debuggingFunctions)
        fprintf(log_others, "native function call = %s offset: %d\n", funcName.c_str(), (cur_pc -base - 0x1000));
      if(debuggingOther)
        fprintf(log_functions, "native function call = %s offset: %d\n", funcName.c_str(), (cur_pc -base - 0x1000));

      target_ulong native_method_size = oat_module_sizes[(cur_pc - base - 0x1000)];
      target_ulong native_method_end = cur_pc + native_method_size;
      target_ulong native_method_begin = cur_pc;

      fprintf(log_functions, " start: 0x%x, end: 0x%x\n", native_method_begin, native_method_end);

      while(native_method_end != native_method_begin) 
      {
        // if(byte_addrs_written[cr3].count(native_method_begin)) 
        // {
        //   increment_something("num_dirty_native_methods");
        //   setInJson("dirty_native_code", "true");
        //   break;
        // }
        if(self_modifying_addrs.empty())
              break;
        if(self_modifying_addrs.count(native_method_begin)) {
          if(debuggingFunctions)
            fprintf(log_functions, "self self-modifying happens in :%s\n", funcName.c_str());
        }
        ++native_method_begin;
      }
      if(debuggingFunctions)
        fflush(log_functions);
    }// end if (oat_module_offsets.count((cur_pc - base - 0x1000)))
  }//end if (base_to_offsets.count(base))
}

static void register_hooks() 
{
  block_begin_cb_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb, NULL);
  memwrite_handle = DECAF_register_callback(DECAF_MEM_WRITE_CB, hook_writes, NULL);
  module_load_handle = VMI_register_callback(VMI_LOADMODULE_CB, &module_load_cb, NULL);
  //dalvik_insn_cb_handle = Dalvik_VMI_register_callback(DALVIK_INSN_BEGIN_CB, handle_instruction, NULL);
}

static void createproc_callback(VMI_Callback_Params* params)
{
  if (targetpid == 0 && strlen(targetname) > 1 && strstr(params->cp.name, targetname) != 0) 
  {
    targetpid = params->cp.pid;
    targetcr3 = params->cp.cr3;
    targetcr3s.insert(targetcr3);
    targetPids.insert(targetpid);

    strncpy(actualname, params->cp.name, strlen(params->cp.name));
    actualname[511] = '\0';

    register_hooks();
    DECAF_printf("process found: pid=%08x, cr3=%08x, name = %s\n", targetpid, targetcr3, params->cp.name);
  }
  else if (targetpid != 0 && params->cp.parent_pid == targetpid)
  {
    targetcr3s.insert(params->cp.cr3);
    DECAF_printf("child process found: pid=%08x, cr3=%08x, name = %s\n", params->cp.pid, params->cp.cr3, params->cp.name);
    increment_something("child_processes");
  }
}

// setup process name
void process_name(const char* proc_name, char* process_hash)
{
  if (strlen(proc_name) < 512) 
  {
    strncpy(targetname, proc_name, strlen(proc_name));

    if(debuggingFunctions)
    {
      std::string name1 = dumps_dir + "functions.log";
      log_functions = fopen(name1.c_str(), "w+");
    }

    if(debuggingOther)
    {
      std::string name2 = dumps_dir + "others.log";
      log_others = fopen(name2.c_str(), "w+");
    }

    if(debuggingModule)
    {
      std::string name3 = dumps_dir + "modules.log";
      log_modules = fopen(name3.c_str(), "w+");
    }

    if(debuggingMW)
    {
      std::string name4 = dumps_dir + "mw.log";
      log_mw = fopen(name4.c_str(), "w+");
    }
    
    jsonInit();
    setInJson("hash", proc_name);
  }
}

static void do_hookapitests(Monitor* mon, const char* proc_name) 
{
  process_name(proc_name, NULL);
  targetname[511] = '\0';
}

static void do_clear_log(Monitor* mon, char* command) {}

static int hookapitests_init(void) 
{
  art::InitLogging(nullptr);
  art::MemMap::Init();

  mkdtemp(dir_name);
  temp_dir_name = dir_name;
  targetname[0] = '\0';

  // register for process create and process remove events
  processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &createproc_callback, NULL);
  return (0);
}

static void hookapitests_cleanup(void) 
{
  if (processbegin_handle != DECAF_NULL_HANDLE) 
  {
    VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);
    processbegin_handle = DECAF_NULL_HANDLE;
  }

  if (module_load_handle != DECAF_NULL_HANDLE) 
  {
    VMI_unregister_callback(VMI_LOADMODULE_CB, module_load_handle);
    module_load_handle = DECAF_NULL_HANDLE;
  }

  if (block_begin_cb_handle != DECAF_NULL_HANDLE)
    DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb_handle);

  if (insn_begin_handle != DECAF_NULL_HANDLE)
    DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, insn_begin_handle);

  if (memwrite_handle != DECAF_NULL_HANDLE)
    DECAF_unregister_callback(DECAF_MEM_WRITE_CB, memwrite_handle);

  // if (dalvik_insn_cb_handle != DECAF_NULL_HANDLE)
  //   Dalvik_VMI_unregister_callback(DALVIK_INSN_BEGIN_CB, dalvik_insn_cb_handle);

  base_to_offsets.clear();
  base_to_sizes.clear();

  if(debuggingOther)
    fclose(log_others);
  if(debuggingFunctions)
    fclose(log_functions);
  if(debuggingModule)
    fclose(log_modules);
  if(debuggingMW)
    fclose(log_mw);
}

static mon_cmd_t hookapitests_term_cmds[] = {
#include "plugin_cmds.h"
    {
        NULL, NULL,
    },
};

extern "C" plugin_interface_t* init_plugin(void)
{
  hookapitests_interface.mon_cmds = hookapitests_term_cmds;
  hookapitests_interface.plugin_cleanup = &hookapitests_cleanup;

  // initialize the plugin
  hookapitests_init();
  return (&hookapitests_interface);
}

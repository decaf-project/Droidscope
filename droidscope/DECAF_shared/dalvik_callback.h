/*
 * dalvik_callback.h
 *
 *  Created on: Sep 16, 2015
 *      Author: Abhishek Vasisht Bhaskar
 */

 
#ifndef DALVIK_VMI_CALLBACK_H_
#define DALVIK_VMI_CALLBACK_H_

#ifdef __cplusplus
extern "C" {
#endif


#include "DECAF_shared/DECAF_types.h"

#define METHOD_NAME_MAX 256
#define DALVIK_FILE_NAME_MAX 256

typedef enum {
  DALVIK_INSN_BEGIN_CB = 0,
  DALVIK_METHOD_BEGIN_CB,
  DS_LAST_CB, //place holder for the last position, no other uses.
} Dalvik_callback_type_t;


typedef struct _DalvikInsnBegin_Params
{
  CPUArchState* env;
  target_ulong dalvik_pc;
  uint32_t insn;
  target_ulong dalvik_file_base;
  
} DalvikInsnBegin_Params;

typedef struct _DalvikMethodBegin_Params
{
  CPUArchState* env;
  char method_name[METHOD_NAME_MAX];
  char dalvik_file_name[DALVIK_FILE_NAME_MAX];
  target_ulong file_base;
  gva_t dalvik_pc;
  
} DalvikMethodBegin_Params;

typedef union _Dalvik_VMI_Callback_Params
{
  DalvikInsnBegin_Params ib;
  DalvikMethodBegin_Params mb;
} Dalvik_VMI_Callback_Params;

typedef void (*Dalvik_VMI_callback_func_t) (Dalvik_VMI_Callback_Params* params);

DECAF_Handle Dalvik_VMI_register_callback(
                Dalvik_callback_type_t cb_type,
                Dalvik_VMI_callback_func_t cb_func,
                int *cb_cond
                );

int Dalvik_VMI_unregister_callback(Dalvik_callback_type_t cb_type, DECAF_Handle handle);


#ifdef __cplusplus
}
#endif

#endif /* DALVIK_VMI_CALLBACK_H_ */





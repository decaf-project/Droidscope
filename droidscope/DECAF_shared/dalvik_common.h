/**
 * Copyright (C) <2015> <Syracuse System Security (Sycure) Lab>
 *
 * This library is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @author Abhishek Vasisht Bhaskar
 * @date 15th September 2015
 */


#ifndef DALVIK_COMMON_H
#define DALVIK_COMMON_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "DECAF_shared/DECAF_types.h"
#include "dalvik/vm/DvmDex.h"
#include "dalvik/libdex/DexProto.h"
#include "dalvik/vm/oo/Object.h"
#include "dalvik/vm/oo/Class.h"
#include "dalvik/vm/oo/Array.h"
#include "DECAF_shared/linux_vmi_.h"

/**
 * These functions have target specific implementations
**/
target_ulong getDalvikPC(CPUArchState* env);
target_ulong getDalvikFP(CPUArchState* env);
target_ulong getDalvikSELF(CPUArchState* env);
target_ulong getDalvikINST(CPUArchState* env);
target_ulong getDalvikIBASE(CPUArchState* env);

#ifdef __cplusplus
}
#endif

#endif
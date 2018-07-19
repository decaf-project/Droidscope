#ifndef BASES_MAP_H
#define BASES_MAP_H

#include "inttypes.h"

#ifdef __cplusplus
extern "C" {
#endif

void insert_base_page(uint32_t base);

void insert_base(uint32_t base);

int check_base_page(uint32_t base);

int check_base(uint32_t base);

#ifdef __cplusplus
} // extern "C" 
#endif

#endif //BASES_MAP_H
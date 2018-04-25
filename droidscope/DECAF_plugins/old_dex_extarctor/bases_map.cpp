#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string.h>
#include <random>
#include <sstream>

#include "bases_map.h"

std::unordered_set<uint32_t> dirty_page_bases;

std::unordered_set<uint32_t> dirty_bases;

void insert_base(uint32_t base)
{
	dirty_bases.insert(base);
}

int check_base(uint32_t base)
{
	return dirty_bases.count(base);
}

void insert_base_page(uint32_t base)
{
	dirty_page_bases.insert(base);
}

int check_base_page(uint32_t base)
{
	return dirty_page_bases.count(base);
}

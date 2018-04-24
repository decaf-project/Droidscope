
#ifndef DEXDUMP_H_
#define DEXDUMP_H_

void dumpOneInstruction(void* pDexFile, const u2* insns, char *output);

void * dexFileParseWrap(const u1 * data,size_t length,int flags);

#endif
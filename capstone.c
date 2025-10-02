#include <stdio.h>
#include <capstone/capstone.h>

extern int main(); // anchor for program text

int test_capstone_program() {
    csh handle;
    cs_insn *insn;
    size_t count;

    // Initialize Capstone for ARM64
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return -1;
    }

    // Pointer to start of main; disassemble ~1KB of code
    unsigned char *start = (unsigned char*)&main;
    size_t size = 1024; // adjust if you want more

    count = cs_disasm(handle, start, size, (uint64_t)start, 0, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            printf("0x%llx:\t%s\t%s\n",
                insn[i].address,
                insn[i].mnemonic,
                insn[i].op_str);
        }
        cs_free(insn, count);
    }

    cs_close(&handle);
    return (int)count;
}

#include <stdio.h>
#include <capstone/capstone.h>

int disasm_function(void *func_ptr, int size) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return -1;

    unsigned char *code = (unsigned char*)func_ptr;

    count = cs_disasm(handle, code, size, (uint64_t)code, 0, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++)
            printf("0x%llx:\t%s\t%s\n",
                insn[i].address,
                insn[i].mnemonic,
                insn[i].op_str);

        cs_free(insn, count);
    }

    cs_close(&handle);
    return (int)count;
}

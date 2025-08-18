#include <stdint.h>
// Snippets of more complicated structs from ruby.h

#define IMMEDIATE_TABLE_SIZE 54 /* a multiple of 9, and < 128 */

struct succ_index_table {
    uint64_t imm_part[IMMEDIATE_TABLE_SIZE / 9];
    struct succ_dict_block {
        unsigned int rank;
        uint64_t small_block_ranks; /* 9 bits * 7 = 63 bits */
        uint64_t bits[512/64];
    } succ_part[0];
};

int main(int argc, char *argv[]) {
	struct succ_index_table _idx_table;
	return 0;
}

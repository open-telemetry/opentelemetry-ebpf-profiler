#include "bpfdefs.h"
#include "types.h"


struct bpf_map_def SEC("maps") system_config = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(SystemConfig),
    .max_entries = 1,
};

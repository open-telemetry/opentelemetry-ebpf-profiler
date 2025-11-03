#define ADDR_MASK_48_BIT 0x0000FFFFFFFFFFFFULL // Lower 48 bits for address
#define EXTRA_TYPE_MASK  0x00FF000000000000ULL // Bits 48-55 for uint8

#define FRAME_TYPE_NONE      0
#define FRAME_TYPE_CME_ISEQ  1
#define FRAME_TYPE_CME_CFUNC 2
#define FRAME_TYPE_ISEQ      3
#define FRAME_TYPE_GC        4

// https://github.com/ruby/ruby/blob/v3_4_5/gc/default/default.c#L438-L443
#define GC_MODE_NONE       0
#define GC_MODE_MARKING    1
#define GC_MODE_SWEEPING   2
#define GC_MODE_COMPACTING 3

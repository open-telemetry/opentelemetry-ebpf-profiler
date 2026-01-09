#define ADDR_MASK_48_BIT 0x0000FFFFFFFFFFFFULL // Lower 48 bits for address
#define EXTRA_TYPE_MASK  0x000F000000000000ULL // Bits 49-52 for Frame type

#define FRAME_TYPE_NONE      0
#define FRAME_TYPE_CME_ISEQ  1
#define FRAME_TYPE_CME_CFUNC 2
#define FRAME_TYPE_ISEQ      3

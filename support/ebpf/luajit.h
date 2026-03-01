// Assigned in HA to anonymous executable virtual memory ranges in the nginx process.
#define LUAJIT_JIT_FILE_ID 42

// Special value for FFI functions
#define LUAJIT_FFI_FUNC 0xff1

// A normal LuaJIT frame
#define LUAJIT_NORMAL_FRAME 0

// A fake "frame" that just reports the G pointer.
#define LUAJIT_G_REPORT 0xff2

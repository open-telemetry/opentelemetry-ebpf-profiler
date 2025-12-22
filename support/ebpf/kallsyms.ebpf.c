#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// kprobe__kallsyms notifies user space about changes to kallsyms.
SEC("kprobe/kallsysms")
int kprobe__kallsyms(void *ctx)
{
  event_send_trigger(ctx, EVENT_TYPE_RELOAD_KALLSYMS);
  return 0;
}

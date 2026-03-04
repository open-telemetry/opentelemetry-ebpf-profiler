// mock_cupti.c — Self-contained mock CUPTI for end-to-end USDT probe testing.
//
// Provides minimal CUPTI type definitions (no CUDA SDK headers needed) and mock
// API functions that libparcagpucupti.so resolves via dlopen.  Helper functions
// (init_parcagpu, simulate_kernel_launch, simulate_buffer_completion,
// cleanup_parcagpu) are called from Go via CGo to drive the probes.

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Minimal CUPTI type definitions — ABI-compatible with real CUPTI headers.
// ============================================================================

typedef int CUptiResult;
#define CUPTI_SUCCESS                  0
#define CUPTI_ERROR_MAX_LIMIT_REACHED  21

typedef void *CUpti_SubscriberHandle;
typedef void *CUcontext;

typedef enum {
  CUPTI_CB_DOMAIN_RUNTIME_API = 2,
  CUPTI_CB_DOMAIN_DRIVER_API  = 3,
} CUpti_CallbackDomain;

typedef uint32_t CUpti_CallbackId;

#define CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000 164
#define CUPTI_ACTIVITY_KIND_KERNEL            3
#define CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL 10
#define CUPTI_ACTIVITY_FLAG_FLUSH_FORCED      1

typedef enum {
  CUPTI_API_ENTER = 0,
  CUPTI_API_EXIT  = 1,
} CUpti_ApiCallbackSite;

typedef struct {
  uint32_t correlationId;
  CUpti_ApiCallbackSite callbackSite;
  const char *symbolName;
  const char *functionName;
} CUpti_CallbackData;

typedef void (*CUpti_CallbackFunc)(void *userdata,
                                   CUpti_CallbackDomain domain,
                                   CUpti_CallbackId cbid,
                                   const CUpti_CallbackData *cbdata);

typedef struct {
  uint32_t kind;
} CUpti_Activity;

typedef uint32_t CUpti_ActivityKind;

// CUpti_ActivityKernel5 — must be 160 bytes, matching cupti_activity_bpf.h.
// Only fields needed by the test and by cupti-prof.c are named.
typedef struct {
  uint32_t kind;            // offset 0
  uint8_t  _pad1[12];       // offset 4
  uint64_t start;           // offset 16
  uint64_t end;             // offset 24
  uint64_t completed;       // offset 32
  uint32_t deviceId;        // offset 40
  uint32_t contextId;       // offset 44
  uint32_t streamId;        // offset 48
  uint8_t  _pad2[40];       // offset 52
  uint32_t correlationId;   // offset 92
  int64_t  gridId;          // offset 96
  const char *name;         // offset 104 (user-space pointer)
  uint64_t _reserved0;      // offset 112
  uint64_t queued;          // offset 120
  uint64_t submitted;       // offset 128
  uint8_t  _pad3[8];        // offset 136
  uint64_t graphNodeId;     // offset 144
  uint32_t shmemLimitCfg;   // offset 152
  uint32_t graphId;         // offset 156
} __attribute__((aligned(8))) CUpti_ActivityKernel5;

_Static_assert(sizeof(CUpti_ActivityKernel5) == 160,
               "CUpti_ActivityKernel5 size must be 160 bytes");

typedef void (*CUpti_BufferRequestFunc)(uint8_t **buffer, size_t *size,
                                        size_t *maxNumRecords);
typedef void (*CUpti_BufferCompletedFunc)(CUcontext ctx, uint32_t streamId,
                                          uint8_t *buffer, size_t size,
                                          size_t validSize);

// ============================================================================
// Global storage for registered callbacks (exported so dlopen'd .so resolves
// them by symbol name).
// ============================================================================

CUpti_CallbackFunc          __cupti_runtime_api_callback        = NULL;
void                       *__cupti_runtime_api_userdata        = NULL;
CUpti_BufferRequestFunc     __cupti_buffer_requested_callback   = NULL;
CUpti_BufferCompletedFunc   __cupti_buffer_completed_callback   = NULL;

// ============================================================================
// Mock CUPTI API functions — resolved by the dlopen'd .so.
// ============================================================================

CUptiResult cuptiActivityFlushPeriod(uint32_t period) {
  (void)period;
  return CUPTI_SUCCESS;
}

CUptiResult cuptiGetResultString(CUptiResult result, const char **str) {
  static const char *ok  = "CUPTI_SUCCESS";
  static const char *err = "CUPTI_ERROR";
  *str = (result == CUPTI_SUCCESS) ? ok : err;
  return CUPTI_SUCCESS;
}

CUptiResult cuptiSubscribe(CUpti_SubscriberHandle *subscriber,
                            CUpti_CallbackFunc callback, void *userdata) {
  __cupti_runtime_api_callback = callback;
  __cupti_runtime_api_userdata = userdata;
  *subscriber = (CUpti_SubscriberHandle)0x1234;
  return CUPTI_SUCCESS;
}

CUptiResult cuptiEnableCallback(uint32_t enable,
                                 CUpti_SubscriberHandle subscriber,
                                 CUpti_CallbackDomain domain,
                                 CUpti_CallbackId cbid) {
  (void)enable; (void)subscriber; (void)domain; (void)cbid;
  return CUPTI_SUCCESS;
}

CUptiResult cuptiActivityRegisterCallbacks(
    CUpti_BufferRequestFunc funcBufferRequested,
    CUpti_BufferCompletedFunc funcBufferCompleted) {
  __cupti_buffer_requested_callback = funcBufferRequested;
  __cupti_buffer_completed_callback = funcBufferCompleted;
  return CUPTI_SUCCESS;
}

CUptiResult cuptiActivityEnable(CUpti_ActivityKind kind) {
  (void)kind;
  return CUPTI_SUCCESS;
}

CUptiResult cuptiActivityFlushAll(uint32_t flag) {
  (void)flag;
  return CUPTI_SUCCESS;
}

// Track iteration state per buffer.
static struct { uint8_t *buffer; size_t offset; } iter_state = {NULL, 0};

CUptiResult cuptiActivityGetNextRecord(uint8_t *buffer,
                                        size_t validBufferSizeBytes,
                                        CUpti_Activity **record) {
  if (iter_state.buffer != buffer) {
    iter_state.buffer = buffer;
    iter_state.offset = 0;
  }
  if (iter_state.offset >= validBufferSizeBytes) {
    iter_state.buffer = NULL;
    iter_state.offset = 0;
    return CUPTI_ERROR_MAX_LIMIT_REACHED;
  }
  *record = (CUpti_Activity *)(buffer + iter_state.offset);
  iter_state.offset += sizeof(CUpti_ActivityKernel5);
  return CUPTI_SUCCESS;
}

CUptiResult cuptiActivityGetNumDroppedRecords(CUcontext context,
                                               uint32_t streamId,
                                               size_t *dropped) {
  (void)context; (void)streamId;
  *dropped = 0;
  return CUPTI_SUCCESS;
}

CUptiResult cuptiUnsubscribe(CUpti_SubscriberHandle subscriber) {
  (void)subscriber;
  return CUPTI_SUCCESS;
}

// ============================================================================
// Helper functions called from Go via CGo.
// ============================================================================

typedef int (*InitializeInjectionFunc)(void);

// Callback pointers extracted after InitializeInjection.
static CUpti_CallbackFunc      parcagpuCallback   = NULL;
static CUpti_BufferRequestFunc bufferReqCallback  = NULL;
static CUpti_BufferCompletedFunc bufferCompCallback = NULL;
static void                    *soHandle           = NULL;

// init_parcagpu loads the .so, calls InitializeInjection, and extracts
// the callback pointers that were registered via the mock CUPTI APIs.
int init_parcagpu(const char *so_path) {
  soHandle = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
  if (!soHandle) {
    fprintf(stderr, "mock_cupti: dlopen failed: %s\n", dlerror());
    return -1;
  }

  InitializeInjectionFunc initFunc =
      (InitializeInjectionFunc)dlsym(soHandle, "InitializeInjection");
  if (!initFunc) {
    fprintf(stderr, "mock_cupti: dlsym(InitializeInjection) failed: %s\n",
            dlerror());
    dlclose(soHandle);
    soHandle = NULL;
    return -1;
  }

  int rc = initFunc();
  fprintf(stderr, "mock_cupti: InitializeInjection returned %d\n", rc);

  // Extract callbacks set by InitializeInjection via our mock CUPTI.
  parcagpuCallback  = __cupti_runtime_api_callback;
  bufferReqCallback = __cupti_buffer_requested_callback;
  bufferCompCallback = __cupti_buffer_completed_callback;

  if (!parcagpuCallback) {
    fprintf(stderr, "mock_cupti: parcagpuCuptiCallback is NULL\n");
    return -1;
  }
  if (!bufferReqCallback || !bufferCompCallback) {
    fprintf(stderr, "mock_cupti: buffer callbacks are NULL\n");
    return -1;
  }

  return 0;
}

// simulate_kernel_launch calls the parcagpuCuptiCallback with a runtime API
// ENTER then EXIT for cudaLaunchKernel_v7000, triggering the cuda_correlation
// USDT probe.
void simulate_kernel_launch(uint32_t correlation_id) {
  if (!parcagpuCallback) return;

  CUpti_CallbackData cbdata;
  memset(&cbdata, 0, sizeof(cbdata));
  cbdata.correlationId = correlation_id;
  cbdata.symbolName    = NULL;
  cbdata.functionName  = "cudaLaunchKernel";

  // ENTER
  cbdata.callbackSite = CUPTI_API_ENTER;
  parcagpuCallback(NULL, CUPTI_CB_DOMAIN_RUNTIME_API,
                   CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000, &cbdata);

  // EXIT — this is where the USDT probe fires.
  cbdata.callbackSite = CUPTI_API_EXIT;
  parcagpuCallback(NULL, CUPTI_CB_DOMAIN_RUNTIME_API,
                   CUPTI_RUNTIME_TRACE_CBID_cudaLaunchKernel_v7000, &cbdata);
}

// simulate_buffer_completion requests a buffer, fills it with one
// CUpti_ActivityKernel5 record, and completes it — triggering the
// kernel_executed and activity_batch USDT probes.
void simulate_buffer_completion(uint32_t correlation_id, uint32_t device_id,
                                uint32_t stream_id, const char *kernel_name) {
  if (!bufferReqCallback || !bufferCompCallback) return;

  uint8_t *buffer = NULL;
  size_t bufSize  = 0;
  size_t maxRec   = 0;
  bufferReqCallback(&buffer, &bufSize, &maxRec);
  if (!buffer || bufSize < sizeof(CUpti_ActivityKernel5)) {
    fprintf(stderr, "mock_cupti: bufferRequested returned bad buffer\n");
    return;
  }

  // Fill one activity record.
  CUpti_ActivityKernel5 *k = (CUpti_ActivityKernel5 *)buffer;
  memset(k, 0, sizeof(*k));
  k->kind          = CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL;
  k->correlationId = correlation_id;
  k->deviceId      = device_id;
  k->streamId      = stream_id;
  k->start         = 1000000;
  k->end           = 2000000;
  k->graphId       = 0;
  k->graphNodeId   = 0;
  k->name          = kernel_name;

  // Complete the buffer — this triggers parcagpuBufferCompleted which fires
  // kernel_executed and activity_batch USDT probes.
  bufferCompCallback(NULL, stream_id, buffer, bufSize,
                     sizeof(CUpti_ActivityKernel5));
}

// cleanup_parcagpu calls the .so's cleanup and closes the handle.
void cleanup_parcagpu(void) {
  if (soHandle) {
    typedef void (*CleanupFunc)(void);
    CleanupFunc cleanup = (CleanupFunc)dlsym(soHandle, "cleanup");
    if (cleanup) {
      cleanup();
    }

    // Clear callback globals to prevent dangling calls.
    __cupti_runtime_api_callback      = NULL;
    __cupti_buffer_requested_callback = NULL;
    __cupti_buffer_completed_callback = NULL;

    parcagpuCallback  = NULL;
    bufferReqCallback = NULL;
    bufferCompCallback = NULL;

    dlclose(soHandle);
    soHandle = NULL;
  }
}

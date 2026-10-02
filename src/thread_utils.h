#import <mach/arm/thread_status.h>
#import <mach/thread_status.h>
#import <mach/mach.h>
#import <mach/error.h>
#import <CoreFoundation/CoreFoundation.h>


#define STACK_SIZE 65536
static uint64_t ropLoop;

#if __DARWIN_OPAQUE_ARM_THREAD_STATE64
#define FP_UNIFIED __opaque_fp
#define LR_UNIFIED __opaque_lr
#define SP_UNIFIED __opaque_sp
#define PC_UNIFIED __opaque_pc
#define FLAGS_UNIFIED __opaque_flags
#define REGISTER_TYPE void*
#else
#define FP_UNIFIED __fp
#define LR_UNIFIED __lr
#define SP_UNIFIED __sp
#define PC_UNIFIED __pc
#define FLAGS_UNIFIED __pad
#define REGISTER_TYPE uint64_t
#endif

struct arm64_thread_full_state {
	arm_thread_state64_t    thread;
	arm_exception_state64_t exception;
	arm_neon_state64_t      neon;
	arm_debug_state64_t     debug;
	uint32_t                thread_valid:1,
							exception_valid:1,
							neon_valid:1,
							debug_valid:1,
							cpmu_valid:1;
};

extern struct arm64_thread_full_state* thread_save_state_arm64(thread_act_t thread);
extern bool thread_restore_state_arm64(thread_act_t thread, struct arm64_thread_full_state* state);
extern kern_return_t wait_for_thread(thread_act_t thread, uint64_t pcToWait, struct arm_unified_thread_state* stateOut);
extern void printThreadState_state(struct arm_unified_thread_state threadState);
extern void printThreadState(thread_act_t thread);
extern void printThreadInfo(thread_act_t thread);
kern_return_t suspend_threads_except_for(thread_act_array_t allThreads, mach_msg_type_number_t threadCount, thread_act_t exceptForThread);
kern_return_t resume_threads_except_for(thread_act_array_t allThreads, mach_msg_type_number_t threadCount, thread_act_t exceptForThread);

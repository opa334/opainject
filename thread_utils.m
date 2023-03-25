#import "thread_utils.h"

#import <stdio.h>
#import <unistd.h>
#import <stdlib.h>

#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach-o/dyld_images.h>

struct arm64_thread_full_state* thread_save_state_arm64(thread_act_t thread)
{
	struct arm64_thread_full_state* s = malloc(sizeof(struct arm64_thread_full_state));
	mach_msg_type_number_t count;
	kern_return_t kr;

	// ARM_THREAD_STATE64
	count = ARM_THREAD_STATE64_COUNT;
	kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &s->thread, &count);
	s->thread_valid = (kr == KERN_SUCCESS);
	if (kr != KERN_SUCCESS) {
		printf("ERROR: Failed to save ARM_THREAD_STATE64 state: %s", mach_error_string(kr));
		free(s);
		return NULL;
	}
	// ARM_EXCEPTION_STATE64
	count = ARM_EXCEPTION_STATE64_COUNT;
	kr = thread_get_state(thread, ARM_EXCEPTION_STATE64,
			(thread_state_t) &s->exception, &count);
	s->exception_valid = (kr == KERN_SUCCESS);
	if (kr != KERN_SUCCESS) {
		printf("WARNING: Failed to save ARM_EXCEPTION_STATE64 state: %s", mach_error_string(kr));
	}
	// ARM_NEON_STATE64
	count = ARM_NEON_STATE64_COUNT;
	kr = thread_get_state(thread, ARM_NEON_STATE64, (thread_state_t) &s->neon, &count);
	s->neon_valid = (kr == KERN_SUCCESS);
	if (kr != KERN_SUCCESS) {
		printf("WARNING: Failed to save ARM_NEON_STATE64 state: %s", mach_error_string(kr));
	}
	// ARM_DEBUG_STATE64
	count = ARM_DEBUG_STATE64_COUNT;
	kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t) &s->debug, &count);
	s->debug_valid = (kr == KERN_SUCCESS);
	if (kr != KERN_SUCCESS) {
		printf("WARNING: Failed to save ARM_DEBUG_STATE64 state: %s", mach_error_string(kr));
	}

	return s;
}

bool thread_restore_state_arm64(thread_act_t thread, struct arm64_thread_full_state* state)
{
	struct arm64_thread_full_state *s = (void *) state;
	kern_return_t kr;
	bool success = true;
	// ARM_THREAD_STATE64
	if (s->thread_valid) {
		kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t) &s->thread, ARM_THREAD_STATE64_COUNT);
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to restore ARM_THREAD_STATE64 state: %s", mach_error_string(kr));
			success = false;
		}
	}
	// ARM_EXCEPTION_STATE64
	if (s->exception_valid) {
		kr = thread_set_state(thread, ARM_EXCEPTION_STATE64, (thread_state_t) &s->exception, ARM_EXCEPTION_STATE64_COUNT);
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to restore ARM_EXCEPTION_STATE64 state: %s", mach_error_string(kr));
			success = false;
		}
	}
	// ARM_NEON_STATE64
	if (s->neon_valid) {
		kr = thread_set_state(thread, ARM_NEON_STATE64, (thread_state_t) &s->neon, ARM_NEON_STATE64_COUNT);
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to restore ARM_NEON_STATE64 state: %s", mach_error_string(kr));
			success = false;
		}
	}
	// ARM_DEBUG_STATE64
	if (s->debug_valid) {
		kr = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t) &s->debug, ARM_DEBUG_STATE64_COUNT);
		if (kr != KERN_SUCCESS) {
			printf("ERROR: Failed to restore ARM_DEBUG_STATE64 state: %s", mach_error_string(kr));
			success = false;
		}
	}
	// Now free the struct.
	free(s);
	return success;
}

kern_return_t wait_for_thread(thread_act_t thread, uint64_t pcToWait, struct arm_unified_thread_state* stateOut)
{
	mach_msg_type_number_t stateToObserveCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state stateToObserve;

	int errCount = 0;
	while(1)
	{
		kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&stateToObserve.ts_64, &stateToObserveCount);
		if(kr != KERN_SUCCESS)
		{
			if (pcToWait == 0) return kr;

			errCount++;
			if(errCount >= 5)
			{
				return kr;
			}
			continue;
		}

		errCount = 0;

		// wait until pc matches with infinite loop rop gadget
		uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(stateToObserve.ts_64);
		if(pc == pcToWait) {
			break;
		}
	}

	if(stateOut)
	{
		*stateOut = stateToObserve;
	}

	return KERN_SUCCESS;
}

kern_return_t suspend_threads_except_for(thread_act_array_t allThreads, mach_msg_type_number_t threadCount, thread_act_t exceptForThread)
{
	for (int i = 0; i < threadCount; i++) {
		thread_act_t thread = allThreads[i];
		if (thread != exceptForThread) {
			thread_suspend(thread);
		}
	}
	return KERN_SUCCESS;
}

kern_return_t resume_threads_except_for(thread_act_array_t allThreads, mach_msg_type_number_t threadCount, thread_act_t exceptForThread)
{
	for (int i = 0; i < threadCount; i++) {
		thread_act_t thread = allThreads[i];
		if (thread != exceptForThread) {
			thread_resume(thread);
		}
	}
	return KERN_SUCCESS;
}

void printThreadState_state(struct arm_unified_thread_state threadState)
{
	for(int i = 0; i <= 28; i++)
	{
		printf("x%d = 0x%llX\n", i, threadState.ts_64.__x[i]);
	}
	//printf("fp: 0x%llX\n", (uint64_t)__darwin_arm_thread_state64_get_fp(threadState.ts_64));
	//printf("lr: 0x%llX\n", (uint64_t)__darwin_arm_thread_state64_get_lr(threadState.ts_64));
	//printf("sp: 0x%llX\n", (uint64_t)__darwin_arm_thread_state64_get_sp(threadState.ts_64));
	//printf("pc: 0x%llX\n", (uint64_t)__darwin_arm_thread_state64_get_pc(threadState.ts_64));
	printf("pc: 0x%llX\n", (uint64_t)threadState.ts_64.PC_UNIFIED);
	printf("sp: 0x%llX\n", (uint64_t)threadState.ts_64.SP_UNIFIED);
	printf("fp: 0x%llX\n", (uint64_t)threadState.ts_64.FP_UNIFIED);
	printf("lr: 0x%llX\n", (uint64_t)threadState.ts_64.LR_UNIFIED);
	printf("cpsr: 0x%X\n", threadState.ts_64.__cpsr);
	#if __arm64e__
	printf("flags: 0x%X\n", threadState.ts_64.__opaque_flags);
	#endif
}

void printThreadState(thread_act_t thread)
{
	printf("- THREAD STATE -\n");

	mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state threadState;
	kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&threadState.ts_64, &thread_state_count);
	if(kr != KERN_SUCCESS)
	{
		printf("<Failed to read thread state>\n");
		return;
	}

	printThreadState_state(threadState);
}

void printThreadInfo(thread_act_t thread)
{
	printf("- INFO OF THREAD %d -\n", thread);

	thread_basic_info_data_t basicInfo;
	mach_msg_type_number_t biCount = THREAD_BASIC_INFO_COUNT;
	kern_return_t kr = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)&basicInfo, &biCount);
	if(kr != KERN_SUCCESS)
	{
		printf("<Failed to fetch info>\n");
		return;
	}

	printf("cpu_usage: %d\n", basicInfo.cpu_usage);
	printf("flags: %d\n", basicInfo.flags);
	printf("policy: %d\n", basicInfo.policy);
	printf("run_state: %d\n", basicInfo.run_state);
	printf("sleep_time: %d\n", basicInfo.sleep_time);
	printf("suspend_count: %d\n", basicInfo.suspend_count);

	printf("system_time: %d.%d\n", basicInfo.system_time.seconds, basicInfo.system_time.microseconds);
	printf("user_time: %d.%d\n", basicInfo.user_time.seconds, basicInfo.user_time.microseconds);
}
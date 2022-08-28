#include <stdlib.h>
#include <sys/wait.h>
#include <stdio.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach-o/dyld_images.h>
#import <sys/utsname.h>
#import <string.h>
#import <limits.h>

#include <sys/types.h>
#include <mach/error.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <pthread_spis.h>
#import "pac.h"

#include <mach/arm/thread_status.h>
#include <mach/thread_status.h>
#import "dyld.h"
#import "sandbox.h"
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

vm_address_t writeStringToTask(task_t task, const char* string, size_t* lengthOut)
{
	kern_return_t kr = KERN_SUCCESS;
	vm_address_t remoteString = (vm_address_t)NULL;
	size_t stringLen = strlen(string)+1;

	kr = vm_allocate(task, &remoteString, stringLen, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		printf("ERROR: Unable to memory for string %s: %s\n", string, mach_error_string(kr));
		return 0;
	}

	kr = vm_protect(task, remoteString, stringLen, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteString, stringLen);
		printf("ERROR: Failed to make string %s read/write: %s.\n", string, mach_error_string(kr));
		return kr;
	}

	kr = vm_write(task, remoteString, (vm_address_t)string, stringLen);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteString, stringLen);
		printf("ERROR: Failed to write string %s to memory: %s\n", string, mach_error_string(kr));
		return kr;
	}

	if(lengthOut)
	{
		*lengthOut = stringLen;
	}

	return remoteString;
}

void findRopLoop(task_t task, vm_address_t allImageInfoAddr)
{
	uint32_t inst = CFSwapInt32(0x00000014);
	ropLoop = (uint64_t)scanLibrariesForMemory(task, allImageInfoAddr, (char*)&inst, sizeof(inst), 4);
}

void suspendThreads(thread_act_array_t allThreads, mach_msg_type_number_t threadCount)
{
	for(int i = 1; i < threadCount; i++)
	{
		thread_act_t thread = allThreads[i];
		kern_return_t kr = thread_suspend(thread);
		if(kr != KERN_SUCCESS)
		{
			printf("INFO: Could not suspend thread %d: %s", thread, mach_error_string(kr));
		}
	}
}

void resumeThreads(thread_act_array_t allThreads, mach_msg_type_number_t threadCount)
{
	for(int i = 1; i < threadCount; i++)
	{
		thread_act_t thread = allThreads[i];
		kern_return_t kr = thread_resume(thread);
		if(kr != KERN_SUCCESS)
		{
			printf("INFO: Could not resume thread %d: %s", thread, mach_error_string(kr));
		}
	}
}

void releaseThreads(thread_act_array_t allThreads, mach_msg_type_number_t threadCount)
{
	for(int i = 1; i < threadCount; i++)
	{
		thread_act_t thread = allThreads[i];
		kern_return_t kr = mach_port_destroy(mach_task_self(), thread);
		if(kr != KERN_SUCCESS)
		{
			printf("INFO: Could not destroy thread %d: %s", thread, mach_error_string(kr));
		}
	}
}

// Create an infinitely spinning pthread in target process
kern_return_t createRemotePthread(task_t task, vm_address_t allImageInfoAddr, thread_act_t* remotePthreadOut)
{
	// GATHER OFFSETS

	vm_address_t libSystemPthreadAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_pthread.dylib");
	uint64_t pthread_create_from_mach_threadAddr = remoteDlSym(task, libSystemPthreadAddr, "_pthread_create_from_mach_thread");

	// ALLOCATE STACK

	vm_address_t remoteStack64 = (vm_address_t)NULL;
	kern_return_t kr = KERN_SUCCESS;
	kr = vm_allocate(task, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		printf("ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_protect(task, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		printf("ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	thread_act_t bootstrapThread;

	struct arm_unified_thread_state bootstrapThreadState;
    bzero(&bootstrapThreadState, sizeof(struct arm_unified_thread_state));

	// spawn pthread to infinite loop
	bootstrapThreadState.ash.flavor = ARM_THREAD_STATE64;
	bootstrapThreadState.ash.count = ARM_THREAD_STATE64_COUNT;
	uint64_t sp = (remoteStack64 + (STACK_SIZE / 2));
	__darwin_arm_thread_state64_set_sp(bootstrapThreadState.ts_64, (void*)sp);
	__darwin_arm_thread_state64_set_pc_fptr(bootstrapThreadState.ts_64, make_sym_callable((void*)pthread_create_from_mach_threadAddr));
	__darwin_arm_thread_state64_set_lr_fptr(bootstrapThreadState.ts_64, make_sym_callable((void*)ropLoop)); //when done, go to infinite loop
	bootstrapThreadState.ts_64.__x[0] = sp + 32; // output pthread_t, pointer to stack
	bootstrapThreadState.ts_64.__x[1] = 0x0; // attributes = NULL
	bootstrapThreadState.ts_64.__x[2] = (uint64_t)make_sym_callable((void*)ropLoop); // start_routine = infinite loop
	bootstrapThreadState.ts_64.__x[3] = 0x0; // arg = NULL

	//printThreadState_state(bootstrapThreadState);

	kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&bootstrapThreadState.ts_64, ARM_THREAD_STATE64_COUNT, &bootstrapThread);
	if(kr != KERN_SUCCESS)
	{
		printf("ERROR: Failed to create running thread: %s.\n", mach_error_string(kr));
		return kr;
	}

	printf("Created bootstrap thread... now waiting on finish\n");

	mach_msg_type_number_t stateToObserveCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state stateToObserve;
	while(1)
	{
	    kr = thread_get_state(bootstrapThread, ARM_THREAD_STATE64, (thread_state_t)&stateToObserve.ts_64, &stateToObserveCount);
		if(kr != KERN_SUCCESS)
		{
			printf("ERROR: failed to get thread state in loop: %s\n", mach_error_string(kr));
			return kr;
		}

		// wait until pc matches with infinite loop rop gadget
		uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(stateToObserve.ts_64);
		//printf("%llX vs %llX\n", pc, ropLoop);
		if(pc == ropLoop) {
			printf("bootstrap done!\n");
			kr = thread_terminate(bootstrapThread);
			if (kr != KERN_SUCCESS) {
				printf("Error terminating bootstrap thread: error %s\n", mach_error_string(kr));
			}
            break;
        }
    }

	thread_act_t remotePthread = 0;

	thread_act_array_t allThreads; // gather threads
    mach_msg_type_number_t threadCount;
	kr = task_threads(task, &allThreads, &threadCount);
	if(kr != KERN_SUCCESS)
	{
		task_resume(task);
		printf("ERROR: failed to get threads in task: %s\n", mach_error_string(kr));
		return kr;
	}

	mach_msg_type_number_t stateToCheckCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state stateToCheck;
	for(int i = 0; i < threadCount; i++)
	{
		thread_act_t thread = allThreads[i];
		if(thread == bootstrapThread) continue;

		kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&stateToCheck.ts_64, &stateToCheckCount);
		if(kr != KERN_SUCCESS)
		{
			printf("INFO: failed to get thread state when checking for pthread %d: %s\n", thread, mach_error_string(kr));
			//mach_port_destroy(task, thread);
			continue;
		}

		// the spinning thread is our new pthread
		uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(stateToCheck.ts_64);
		if(pc == ropLoop) 
		{
			remotePthread = thread;
		}
		else
		{
			// if not the thread we want, destroy
			//mach_port_destroy(task, thread);
		}
	}

	if(!remotePthread)
	{
		return -1;
	}

	if(remotePthreadOut)
	{
		*remotePthreadOut = remotePthread;
	}

	return kr;
}

void destroyRemotePthread(task_t task, thread_act_t thread)
{
	thread_terminate(thread);
	//mach_port_destroy(task, thread);
}

kern_return_t arbCall(task_t task, thread_act_t targetThread, uint64_t* retOut, vm_address_t funcPtr, int numArgs, ...)
{
	kern_return_t kr = KERN_SUCCESS;
	if(numArgs > 8)
	{
		printf("ERROR: Only 8 arguments are supported by arbCall\n");
		return -2;
	}
	if(!targetThread)
	{
		printf("ERROR: targetThread == null\n");
		return -3;
	}

	va_list ap;
    va_start(ap, numArgs);

	// suspend target thread
	thread_suspend(targetThread);

	// STEP TWO: backup states of target thread

	mach_msg_type_number_t origThreadStateCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state origThreadState;
	kr = thread_get_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&origThreadState.ts_64, &origThreadStateCount);
	if(kr != KERN_SUCCESS)
	{
		thread_resume(targetThread);
		printf("ERROR: failed to save original state of target thread: %s\n", mach_error_string(kr));
		return kr;
	}

	struct arm64_thread_full_state* origThreadFullState = thread_save_state_arm64(targetThread);
	if(!origThreadFullState)
	{
		thread_resume(targetThread);
		printf("ERROR: failed to backup original state of target thread\n");
		return kr;
	}


	// STEP THREE: prepare target thread for arbitary call

	// allocate stack
	vm_address_t remoteStack = (vm_address_t)NULL;
	kr = vm_allocate(task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		thread_resume(targetThread);
		printf("ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	// make stack read / write
	kr = vm_protect(task, remoteStack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		thread_resume(targetThread);
		printf("ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	// important: abort any existing syscalls by target thread, thanks to Linus Henze for this suggestion :P
	thread_abort(targetThread);

	// set state for arb call
	struct arm_unified_thread_state newState = origThreadState;
	newState.ash.flavor = ARM_THREAD_STATE64;
	newState.ash.count = ARM_THREAD_STATE64_COUNT;
	vm_address_t sp = remoteStack + (STACK_SIZE / 2);
	__darwin_arm_thread_state64_set_sp(newState.ts_64, (void*)sp);
	//const size_t STACK_SKIP = 0x200;
	//__darwin_arm_thread_state64_set_sp(newState.ts_64, __darwin_arm_thread_state64_get_sp(newState.ts_64) - STACK_SKIP);
	__darwin_arm_thread_state64_set_pc_fptr(newState.ts_64, make_sym_callable((void*)funcPtr));
	__darwin_arm_thread_state64_set_lr_fptr(newState.ts_64, make_sym_callable((void*)ropLoop));

	// write arguments into registers
	for (int i = 0; i < numArgs; i++)
	{
		newState.ts_64.__x[i] = va_arg(ap, uint64_t);
	}

	kr = thread_set_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&newState.ts_64, ARM_THREAD_STATE64_COUNT);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		thread_resume(targetThread);
		printf("ERROR: failed to set state for thread: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("Set state for arbitary call\n");
	//printThreadState(targetThread);

	// STEP FOUR: do arbitary call

	printf("Starting task...\n");

	thread_resume(targetThread);


	// STEP FIVE: wait for arbitary call to exit

	mach_msg_type_number_t stateToObserveCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state stateToObserve;
	while(1)
	{
	    kr = thread_get_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&stateToObserve.ts_64, &stateToObserveCount);
		if(kr != KERN_SUCCESS)
		{
			free(origThreadFullState);
			printf("ERROR: failed to get thread state in loop: %s\n", mach_error_string(kr));
			return kr;
		}

		// wait until pc matches with infinite loop rop gadget
		uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(stateToObserve.ts_64);
		if(pc == ropLoop) {
            break;
        }
    }

	// extract return value from state if needed
	if(retOut)
	{
		*retOut = stateToObserve.ts_64.__x[0];
	}

	// release fake stack as it's no longer needed
	vm_deallocate(task, remoteStack, STACK_SIZE);


	// STEP SIX: suspend target thread

	thread_suspend(targetThread);
	thread_abort(targetThread);


	// STEP SEVEN: restore states of target thread to what they were before the arbitary call

	bool restoreSuccess = thread_restore_state_arm64(targetThread, origThreadFullState);
	if(!restoreSuccess)
	{
		printf("ERROR: failed to revert to old thread state\n");
		return kr;
	}


	// STEP EIGHT: resume all threads, process should continue executing as before
	//printThreadState(targetThread);
	thread_resume(targetThread);

	return kr;
}

void prepareForMagic(task_t task, vm_address_t allImageInfoAddr)
{
	// FIND INFINITE LOOP ROP GADGET
	static dispatch_once_t onceToken;
    dispatch_once (&onceToken, ^{
        findRopLoop(task, allImageInfoAddr);
    });
	printf("[prepareForMagic] done, ropLoop: 0x%llX\n", ropLoop);
}

bool sandboxFixup(task_t task, thread_act_t pthread, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	int sandboxExtensionNeeded = sandbox_check(pid, "file-read-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
	if(!sandboxExtensionNeeded)
	{
		printf("[sandboxFixup] not needed, bailing out.\n");
		return YES;
	}

	vm_address_t libSystemSandboxAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_sandbox.dylib");
	uint64_t sandbox_extension_consumeAddr = remoteDlSym(task, libSystemSandboxAddr, "_sandbox_extension_consume");

	printf("[sandboxFixup] applying sandbox extension! sandbox_extension_consume: 0x%llX\n", sandbox_extension_consumeAddr);

	// APPLY SANDBOX EXTENSION FOR DYLIB PATH 
	char* extString = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath, 0);
	size_t remoteExtStringSize = 0;
	vm_address_t remoteExtString = writeStringToTask(task, (const char*)extString, &remoteExtStringSize);
	if(remoteExtString)
	{
		int64_t sandbox_extension_consume_ret = 0;
		arbCall(task, pthread, (uint64_t*)&sandbox_extension_consume_ret, sandbox_extension_consumeAddr, 1, remoteExtString);
		vm_deallocate(task, remoteExtString, remoteExtStringSize);

		printf("[sandboxFixup] sandbox_extension_consume returned %lld\n", (int64_t)sandbox_extension_consume_ret);

		return sandbox_extension_consume_ret == 1;
	}

	return NO;
}

void injectDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);

	thread_act_t pthread = 0;
	kern_return_t kr = createRemotePthread(task, allImageInfoAddr, &pthread);
	if(kr != KERN_SUCCESS)
	{
		printf("[injectDylibViaRop] ERROR: failed to create remote pthread.\n");
		return;
	}
	printf("[injectDylibViaRop] created remote pthread, port: %d\n", pthread);

	sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

	printf("[injectDylibViaRop] Preparation done, now injecting!\n");

	// FIND OFFSETS
	vm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
	uint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen");
	printf("[injectDylibViaRop] dlopen: 0x%llX\n", (unsigned long long)dlopenAddr);

	// CALL DLOPEN
	size_t remoteDylibPathSize = 0;
	vm_address_t remoteDylibPath = writeStringToTask(task, (const char*)dylibPath, &remoteDylibPathSize);
	if(remoteDylibPath)
	{
		void* dlopenRet;
		arbCall(task, pthread, (uint64_t*)&dlopenRet, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
		vm_deallocate(task, remoteDylibPath, remoteDylibPathSize);
		printf("[injectDylibViaRop] dlopen returned %p\n", dlopenRet);
	}

	destroyRemotePthread(task, pthread);
}

// returns remote file descriptor on success, -1 on failure
int preflightDylibViaRop(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	prepareForMagic(task, allImageInfoAddr);

	thread_act_t pthread = 0;
	kern_return_t kr = createRemotePthread(task, allImageInfoAddr, &pthread);
	if(kr != KERN_SUCCESS)
	{
		printf("[preflightDylibViaRop] ERROR: failed to create remote pthread.\n");
		return -1;
	}
	printf("[preflightDylibViaRop] created remote pthread, port: %d\n", pthread);

	sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

	printf("[preflightDylibViaRop] Preparation done, now preflighting!\n");

	// FIND OFFSETS
	vm_address_t libsystem_kernelAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_kernel.dylib");
	uint64_t openAddr = remoteDlSym(task, libsystem_kernelAddr, "_open");
	vm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
	uint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen");

	printf("[preflightDylibViaRop] open: 0x%llX\n", (unsigned long long)openAddr);
	printf("[preflightDylibViaRop] dlopen: 0x%llX\n", (unsigned long long)dlopenAddr);

	size_t remoteDylibPathSize = 0;
	vm_address_t remoteDylibPath = writeStringToTask(task, (const char*)dylibPath, &remoteDylibPathSize);
	if(remoteDylibPath)
	{
		uint64_t fdUint;
		arbCall(task, pthread, &fdUint, openAddr, 3, remoteDylibPath, O_RDONLY, 0);
		printf("[preflightDylibViaRop] open returned %lld\n", fdUint);
		arbCall(task, pthread, NULL, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
		return (int)fdUint;
	}

	return -1;
}
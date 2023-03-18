#import <stdio.h>
#import <unistd.h>
#import <stdlib.h>
#import <dlfcn.h>
#import <errno.h>
#import <string.h>
#import <limits.h>
#import <pthread.h>
#import <pthread_spis.h>
#import <mach/mach.h>
#import <mach/error.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <mach-o/dyld_images.h>
#import <sys/utsname.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <sys/mman.h>
#import <sys/stat.h>
#import <sys/wait.h>
#import <CoreFoundation/CoreFoundation.h>

#import "pac.h"
#import "dyld.h"
#import "sandbox.h"
#import "thread_utils.h"

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

char *copyStringFromTask(task_t task, vm_address_t stringAddress)
{
	extern unsigned char* readProcessMemory(task_t t, mach_vm_address_t addr, mach_msg_type_number_t* size);
	vm_address_t curAddress = stringAddress;
	unsigned char buf = -1;
	while (buf != 0) {
		mach_msg_type_number_t size = 1;
		unsigned char *stringBuf = readProcessMemory(task, curAddress, &size);
		buf = *stringBuf;
		curAddress++;
		vm_deallocate(mach_task_self(), (vm_address_t)stringBuf, size);
	}

	vm_address_t nullByteAddress = curAddress - 1;
	mach_msg_type_number_t stringSize = nullByteAddress - stringAddress;
	return (char *)readProcessMemory(task, stringAddress, &stringSize);
}

void findRopLoop(task_t task, vm_address_t allImageInfoAddr)
{
	uint32_t inst = CFSwapInt32(0x00000014);
	ropLoop = (uint64_t)scanLibrariesForMemory(task, allImageInfoAddr, (char*)&inst, sizeof(inst), 4);
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
		printf("[createRemotePthread] ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_protect(task, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		printf("[createRemotePthread] ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	thread_act_t bootstrapThread = 0;
	struct arm_unified_thread_state bootstrapThreadState;
	memset(&bootstrapThreadState, 0, sizeof(struct arm_unified_thread_state));

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
		printf("[createRemotePthread] ERROR: Failed to create running thread: %s.\n", mach_error_string(kr));
		return kr;
	}

	printf("[createRemotePthread] Created bootstrap thread... now waiting on finish\n");

	struct arm_unified_thread_state outState;
	kr = wait_for_thread(bootstrapThread, ropLoop, &outState);
	if(kr != KERN_SUCCESS)
	{
		printf("[createRemotePthread] ERROR: failed to wait for bootstrap thread: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("[createRemotePthread] Bootstrap done!\n");
	kr = thread_terminate(bootstrapThread);
	if (kr != KERN_SUCCESS) {
		printf("[createRemotePthread] ERROR terminating bootstrap thread: %s\n", mach_error_string(kr));
	}

	thread_act_t remotePthread = 0;

	thread_act_array_t allThreads; // gather threads
	mach_msg_type_number_t threadCount;
	kr = task_threads(task, &allThreads, &threadCount);
	if(kr != KERN_SUCCESS)
	{
		task_resume(task);
		printf("[createRemotePthread] ERROR: failed to get threads in task: %s\n", mach_error_string(kr));
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
			printf("[createRemotePthread] WARNING: failed to get thread state of thread %d when trying to find pthread, error: %s (%d)\n", thread, mach_error_string(kr), kr);
			continue;
		}

		// the spinning thread is our new pthread
		uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(stateToCheck.ts_64);
		if(pc == ropLoop) 
		{
			remotePthread = thread;
		}
	}

	vm_deallocate(mach_task_self(), (vm_offset_t)allThreads, sizeof(thread_act_array_t) * threadCount);

	if(!remotePthread)
	{
		printf("[createRemotePthread] ERROR: Failed to find pthread\n");
		return -1;
	}

	printf("[createRemotePthread] Found pthread: %d\n", remotePthread);

	if(remotePthreadOut)
	{
		*remotePthreadOut = remotePthread;
	}

	return kr;
}

kern_return_t arbCall(task_t task, thread_act_t targetThread, uint64_t* retOut, bool willReturn, vm_address_t funcPtr, int numArgs, ...)
{
	kern_return_t kr = KERN_SUCCESS;
	if(numArgs > 8)
	{
		printf("[arbCall] ERROR: Only 8 arguments are supported by arbCall\n");
		return -2;
	}
	if(!targetThread)
	{
		printf("[arbCall] ERROR: targetThread == null\n");
		return -3;
	}

	va_list ap;
	va_start(ap, numArgs);

	// suspend target thread
	thread_suspend(targetThread);

	// backup states of target thread

	mach_msg_type_number_t origThreadStateCount = ARM_THREAD_STATE64_COUNT;
	struct arm_unified_thread_state origThreadState;
	kr = thread_get_state(targetThread, ARM_THREAD_STATE64, (thread_state_t)&origThreadState.ts_64, &origThreadStateCount);
	if(kr != KERN_SUCCESS)
	{
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to save original state of target thread: %s\n", mach_error_string(kr));
		return kr;
	}

	struct arm64_thread_full_state* origThreadFullState = thread_save_state_arm64(targetThread);
	if(!origThreadFullState)
	{
		thread_resume(targetThread);
		printf("[arbCall] ERROR: failed to backup original state of target thread\n");
		return kr;
	}

	// prepare target thread for arbitary call

	// allocate stack
	vm_address_t remoteStack = (vm_address_t)NULL;
	kr = vm_allocate(task, &remoteStack, STACK_SIZE, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: Unable to allocate stack memory: %s\n", mach_error_string(kr));
		return kr;
	}

	// make stack read / write
	kr = vm_protect(task, remoteStack, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		free(origThreadFullState);
		vm_deallocate(task, remoteStack, STACK_SIZE);
		thread_resume(targetThread);
		printf("[arbCall] ERROR: Failed to make remote stack writable: %s.\n", mach_error_string(kr));
		return kr;
	}

	// abort any existing syscalls by target thread, thanks to Linus Henze for this suggestion :P
	thread_abort(targetThread);

	// set state for arb call
	struct arm_unified_thread_state newState = origThreadState;
	newState.ash.flavor = ARM_THREAD_STATE64;
	newState.ash.count = ARM_THREAD_STATE64_COUNT;
	vm_address_t sp = remoteStack + (STACK_SIZE / 2);
	__darwin_arm_thread_state64_set_sp(newState.ts_64, (void*)sp);
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
		printf("[arbCall] ERROR: failed to set state for thread: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("[arbCall] Set thread state for arbitary call\n");
	//printThreadState(targetThread);

	// perform arbitary call
	thread_resume(targetThread);
	printf("[arbCall] Started thread, waiting for it to finish...\n");

	// wait for arbitary call to finish (or not)
	struct arm_unified_thread_state outState;
	if (willReturn)
	{
		kr = wait_for_thread(targetThread, ropLoop, &outState);
		if(kr != KERN_SUCCESS)
		{
			free(origThreadFullState);
			printf("[arbCall] ERROR: failed to wait for thread to finish: %s\n", mach_error_string(kr));
			return kr;
		}

		// extract return value from state if needed
		if(retOut)
		{
			*retOut = outState.ts_64.__x[0];
		}
	}
	else
	{
		kr = wait_for_thread(targetThread, 0, &outState);
		printf("[arbCall] pthread successfully did not return with code %d (%s)\n", kr, mach_error_string(kr));
	}

	// release fake stack as it's no longer needed
	vm_deallocate(task, remoteStack, STACK_SIZE);

	if (willReturn)
	{
		// suspend target thread
		thread_suspend(targetThread);
		thread_abort(targetThread);

		// restore states of target thread to what they were before the arbitary call
		bool restoreSuccess = thread_restore_state_arm64(targetThread, origThreadFullState);
		if(!restoreSuccess)
		{
			printf("[arbCall] ERROR: failed to revert to old thread state\n");
			return kr;
		}

		// resume thread again, process should continue executing as before
		//printThreadState(targetThread);
		thread_resume(targetThread);
	}

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
		arbCall(task, pthread, (uint64_t*)&sandbox_extension_consume_ret, true, sandbox_extension_consumeAddr, 1, remoteExtString);
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
	if(kr != KERN_SUCCESS) return;

	sandboxFixup(task, pthread, pid, dylibPath, allImageInfoAddr);

	printf("[injectDylibViaRop] Preparation done, now injecting!\n");

	// FIND OFFSETS
	vm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");
	uint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen");
	uint64_t dlerrorAddr = remoteDlSym(task, libDyldAddr, "_dlerror");
	vm_address_t libSystemPthreadAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_pthread.dylib");
	uint64_t pthread_exitAddr = remoteDlSym(task, libSystemPthreadAddr, "_pthread_exit");

	printf("[injectDylibViaRop] dlopen: 0x%llX, dlerror: 0x%llX\n", (unsigned long long)dlopenAddr, (unsigned long long)dlerrorAddr);

	// CALL DLOPEN
	size_t remoteDylibPathSize = 0;
	vm_address_t remoteDylibPath = writeStringToTask(task, (const char*)dylibPath, &remoteDylibPathSize);
	if(remoteDylibPath)
	{
		void* dlopenRet;
		arbCall(task, pthread, (uint64_t*)&dlopenRet, true, dlopenAddr, 2, remoteDylibPath, RTLD_NOW);
		vm_deallocate(task, remoteDylibPath, remoteDylibPathSize);

		if (dlopenRet) {
			printf("[injectDylibViaRop] dlopen succeeded, library handle: %p\n", dlopenRet);
		}
		else {
			uint64_t remoteErrorString = 0;
			arbCall(task, pthread, (uint64_t*)&remoteErrorString, true, dlerrorAddr, 0);
			char *errorString = copyStringFromTask(task, remoteErrorString);
			printf("[injectDylibViaRop] dlopen failed, error:\n%s\n", errorString);
			vm_deallocate(mach_task_self(), (vm_address_t)errorString, strlen(errorString)+1);
		}
	}

	arbCall(task, pthread, NULL, false, pthread_exitAddr, 0);
	//thread_terminate(pthread);
}
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

#include <mach/arm/thread_status.h>
#import "dyld.h"
#import "sandbox.h"
#import <CoreFoundation/CoreFoundation.h>

#define STACK_SIZE 65536

#define	PT_TRACE_ME	0	/* child declares it's being traced */
#define	PT_READ_I	1	/* read word in child's I space */
#define	PT_READ_D	2	/* read word in child's D space */
#define	PT_READ_U	3	/* read word in child's user structure */
#define	PT_WRITE_I	4	/* write word in child's I space */
#define	PT_WRITE_D	5	/* write word in child's D space */
#define	PT_WRITE_U	6	/* write word in child's user structure */
#define	PT_CONTINUE	7	/* continue the child */
#define	PT_KILL		8	/* kill the child process */
#define	PT_STEP		9	/* single step the child */
#define	PT_ATTACH	10	/* trace some running process */
#define	PT_DETACH	11	/* stop tracing a process */
#define	PT_SIGEXC	12	/* signals as exceptions for current_proc */
#define PT_THUPDATE	13	/* signal for thread# */
#define PT_ATTACHEXC	14	/* attach to running process with signal exception */
extern int ptrace(int request, pid_t pid, caddr_t addr, int data);

static kern_return_t runPayload(task_t task, uint8_t* payload, size_t payloadSize, uint64_t codeStart, vm_address_t allImageInfoAddr)
{
	// GATHER OFFSETS

	vm_address_t libSystemPthreadAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_pthread.dylib");
	uint64_t pthread_create_from_mach_threadAddr = remoteDlSym(task, libSystemPthreadAddr, "_pthread_create_from_mach_thread");
	uint64_t pthread_exitAddr = remoteDlSym(task, libSystemPthreadAddr, "_pthread_exit");


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


	// THREAD BOOTSTRAP PAYLOAD (x2: startFunc argument passed to pthread_create_from_mach_thread)

	uint32_t bootstrapCode[7] = {
		// pthread_create_from_mach_thread call
		// arg1: x0, output pthread_t = pointer to stack
		// arg2: x1, attributes = NULL
		// arg3: x2, start_routine, pointer to real payload, passed via thread state
		// arg4: x3, arg, pointer to arguments array = NULL
		CFSwapInt32(0xE0230091), // add x0, sp, #8 ; x0 = SP+8
		CFSwapInt32(0x010080D2), // mov x1, #0x0
		CFSwapInt32(0x030080D2), // mov x3, #0x0
		CFSwapInt32(0x68FFFF58), // ldr x8, -0x14 ; pthread_create_from_mach_threadAddr
		CFSwapInt32(0x00013FD6), // blr x8
		CFSwapInt32(0x490880D2), // mov x9, 0x42 (end code)
		CFSwapInt32(0x00000014), // b #0 (infinite loop)
	};

	uint64_t bootstrapCodeVarCount = 1; // count of variables before code
	size_t bootstrapCodeVarSize = bootstrapCodeVarCount * sizeof(uint64_t);

	size_t bootstrapPayloadSize = bootstrapCodeVarCount * sizeof(uint32_t) + sizeof(bootstrapCode); // allocate needed memory space
	char* bootstrapPayload = malloc(bootstrapPayloadSize);
	bzero(&bootstrapPayload[0], bootstrapPayloadSize);

	intptr_t bootstrapPayloadPtr = (intptr_t)bootstrapPayload; // insert variables
	memcpy((void*)(bootstrapPayloadPtr), (const void*)&pthread_create_from_mach_threadAddr, sizeof(uint64_t));

	memcpy((void*)(bootstrapPayloadPtr+bootstrapCodeVarSize), &bootstrapCode[0], sizeof(bootstrapCode)); //insert code

	vm_address_t remoteBootstrapPayload = (vm_address_t)NULL;
	kr = vm_allocate(task, &remoteBootstrapPayload, bootstrapPayloadSize, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		free(bootstrapPayload);
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		printf("ERROR: Unable to allocate memory for bootstrap code: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_write(task, remoteBootstrapPayload, (vm_address_t)bootstrapPayload, bootstrapPayloadSize);
	if(kr != KERN_SUCCESS)
	{
		free(bootstrapPayload);
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		vm_deallocate(task, remoteBootstrapPayload, bootstrapPayloadSize);
		printf("ERROR: Failed to write payload to code memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_protect(task, remoteBootstrapPayload + bootstrapCodeVarSize, sizeof(bootstrapCode), FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
	if(kr != KERN_SUCCESS)
	{
		free(bootstrapPayload);
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		vm_deallocate(task, remoteBootstrapPayload, bootstrapPayloadSize);
		printf("ERROR: Failed to make bootstrap payload executable: %s\n", mach_error_string(kr));
		return kr;
	}

	/*kr = vm_protect(task, remoteBootstrapPayload, bootstrapCodeVarSize, FALSE, VM_PROT_READ | VM_PROT_WRITE);
	if(kr != KERN_SUCCESS)
	{
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		vm_deallocate(task, remoteBootstrapPayload, bootstrapPayloadSize);
		printf("ERROR: Failed to make bootstrap payload variables read/write: %s\n", mach_error_string(kr));
		return kr;
	}*/

	free(bootstrapPayload);


	// SETUP PAYLOAD SUFFIX (pthread_exit(0))

	uint32_t payloadSuffixCode[3] = {
		CFSwapInt32(0x000080D2), // mov x0, #0
		CFSwapInt32(0x48000058), // ldr x8, 0x8 ; pthread_exit
		CFSwapInt32(0x00013FD6), // blr x8
	};

	uint64_t payloadSuffixVarCount = 1; // count of variables after suffix code
	uint64_t payloadSuffixVarSize = payloadSuffixVarCount * sizeof(uint64_t);
	uint64_t payloadSuffixCodeSize = sizeof(payloadSuffixCode);
	uint64_t payloadSuffixSize = payloadSuffixVarSize + payloadSuffixCodeSize;

	char* payloadSuffix = malloc(payloadSuffixSize); // allocate buffer
	intptr_t payloadSuffixPtr = (intptr_t)payloadSuffix;

	memcpy((void*)(payloadSuffixPtr), &payloadSuffixCode[0], payloadSuffixCodeSize); // insert code
	memcpy((void*)(payloadSuffixPtr+payloadSuffixCodeSize), (const void*)&pthread_exitAddr, sizeof(uint64_t)); // insert variables


	// WRITE PASSED PAYLOAD

	uint64_t fullPayloadSize = payloadSize + payloadSuffixSize;

	vm_address_t remotePayload = (vm_address_t)NULL;
	kr = vm_allocate(task, &remotePayload, fullPayloadSize, VM_FLAGS_ANYWHERE);
	if(kr != KERN_SUCCESS)
	{
		free(payloadSuffix);
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		vm_deallocate(task, remoteBootstrapPayload, bootstrapPayloadSize);
		printf("ERROR: Unable to allocate payload code memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_write(task, remotePayload, (vm_address_t)payload, payloadSize);
	if(kr != KERN_SUCCESS)
	{
		free(payloadSuffix);
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		vm_deallocate(task, remotePayload, fullPayloadSize);
		vm_deallocate(task, remoteBootstrapPayload, bootstrapPayloadSize);
		printf("ERROR: Failed to write payload to code memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_write(task, remotePayload+payloadSize, (vm_address_t)payloadSuffix, payloadSuffixSize);
	if(kr != KERN_SUCCESS)
	{
		free(payloadSuffix);
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		vm_deallocate(task, remotePayload, fullPayloadSize);
		vm_deallocate(task, remoteBootstrapPayload, bootstrapPayloadSize);
		printf("ERROR: Failed to write payload suffix to code memory: %s\n", mach_error_string(kr));
		return kr;
	}

	kr = vm_protect(task, remotePayload + codeStart, fullPayloadSize - codeStart - payloadSuffixVarSize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
	if(kr != KERN_SUCCESS)
	{
		free(payloadSuffix);
		vm_deallocate(task, remoteStack64, STACK_SIZE);
		vm_deallocate(task, remotePayload, fullPayloadSize);
		vm_deallocate(task, remoteBootstrapPayload, bootstrapPayloadSize);
		printf("ERROR: Failed to make code payload executable: %s\n", mach_error_string(kr));
		return kr;
	}

	printf("marked %llX - %llX as rx\n", (uint64_t)remotePayload + codeStart, (uint64_t)remotePayload + (fullPayloadSize - codeStart - payloadSuffixVarSize));


	// ALLOCATE THREAD AND START IT

	thread_act_t remoteThread;

	struct arm_unified_thread_state remoteThreadState64;
	bzero(&remoteThreadState64, sizeof(struct arm_unified_thread_state));

	remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
	remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
	__darwin_arm_thread_state64_set_sp(remoteThreadState64.ts_64, (void*)(remoteStack64 + (STACK_SIZE / 2)));
	__darwin_arm_thread_state64_set_pc_fptr(remoteThreadState64.ts_64, (void*)(remoteBootstrapPayload + bootstrapCodeVarSize));
	remoteThreadState64.ts_64.__x[2] = remotePayload + codeStart; // <- startFunc argument of pthread_create_from_mach_thread call

	printf("About to jump to %llX (thread bootstrap)\n", (uint64_t)__darwin_arm_thread_state64_get_pc_fptr(remoteThreadState64.ts_64));
	printf("Real payload: %llX (code start: %llX)\n", (uint64_t)remotePayload,  (uint64_t)(remotePayload + codeStart));

	// Uncomment to debug issues before the jump to code happens
	//getchar();

	printf("Starting thread in task!\n");
	kr = thread_create_running(task, ARM_THREAD_STATE64, (thread_state_t)&remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT, &remoteThread);
	if(kr != KERN_SUCCESS)
	{
		printf("ERROR: Failed to create running thread: %s.\n", mach_error_string(kr));
	}


	// WAIT FOR THREAD TO FINISH
	// (Note: The pthread this thread spawns will still be running by the time it has fininshed)
	// (So we unfortunately can't release the remote memory again because otherwise the pthread would crash)

	printf("Started thread, now waiting for it to finish.\n");

	mach_msg_type_number_t thread_state_count = ARM_THREAD_STATE64_COUNT;
	for (;;) {
		kr = thread_get_state(remoteThread, ARM_THREAD_STATE64, (thread_state_t)&remoteThreadState64.ts_64, &thread_state_count);
		if (kr != KERN_SUCCESS) {
			printf("Error getting stub thread state: error %s", mach_error_string(kr));
			break;
		}

		// Check whether x9 is 0x42 (exit code)
		if (remoteThreadState64.ts_64.__x[9] == 0x42) {
			printf("Stub thread finished\n");
			kr = thread_terminate(remoteThread);
			if (kr != KERN_SUCCESS) {
				printf("Error terminating stub thread: error %s\n", mach_error_string(kr));
			}
			break;
		}
	}

	printf("Thread finished, we done here.\n");

	// Deallocating is very hard to time right, we just leave the memory in there, doesn't matter too much anyways
	//vm_deallocate(task, remoteStack64, STACK_SIZE);
	//vm_deallocate(task, remoteCode64, payloadSize);
	free(payloadSuffix);
	return kr;
}

int injectDylibViaShellcode(task_t task, pid_t pid, const char* dylibPath, vm_address_t allImageInfoAddr)
{
	// STEP ONE: gather offsets
	
	vm_address_t libSystemSandboxAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libsystem_sandbox.dylib");
	vm_address_t libDyldAddr = getRemoteImageAddress(task, allImageInfoAddr, "/usr/lib/system/libdyld.dylib");

	//uint64_t pthread_set_selfAddr = remoteDlSym(task, libSystemPthreadAddr, "__pthread_set_self");
	
	uint64_t sandbox_extension_consumeAddr = remoteDlSym(task, libSystemSandboxAddr, "_sandbox_extension_consume");
	uint64_t dlopenAddr = remoteDlSym(task, libDyldAddr, "_dlopen");

	printf("sandbox_extension_consumeAddr: %llX\n", (unsigned long long)sandbox_extension_consumeAddr);
	printf("dlopenAddr: %llX\n", (unsigned long long)dlopenAddr);

	// STEP TWO: set up ptrace

	/*kern_return_t ret;
	ret = ptrace(PT_ATTACH, pid, NULL, 0);
	if(ret != KERN_SUCCESS)
	{
		printf("Error attaching to process %d: %d\n", pid, errno);
		return 1;
	}
	ret = ptrace(PT_CONTINUE, pid, NULL, 0);
	if(ret != KERN_SUCCESS)
	{
		printf("Error continuing execution of process %d\n", pid);
		return 1;
	}*/

	// STEP THREE: apply sandbox extension if needed

	// Check whether sandbox extension is needed
	int sandboxExtensionNeeded = sandbox_check(pid, "file-read-data", SANDBOX_FILTER_PATH | SANDBOX_CHECK_NO_REPORT, dylibPath);
	if(sandboxExtensionNeeded)
	{
		printf("Sandbox extension needed, performing magic...\n");

		char* extString = sandbox_extension_issue_file(APP_SANDBOX_READ, dylibPath, 0);
		size_t stringAllocSize = 300;

		uint64_t codeVarCount = 1;
		uint64_t codeVarSize = codeVarCount * sizeof(uint64_t);

		uint32_t code[3] = {
			// sandbox_extension_consume call
			// arg1: x0, pointer to extension string
			CFSwapInt32(0x60F6FF10), // adr x0, -0x134 ; reference to extString
			CFSwapInt32(0xA8FFFF58), // ldr x8, -0x0C ; sandbox_extension_consumeAddr
			CFSwapInt32(0x00013FD6), // blr x8
		};

		size_t payloadSize = stringAllocSize + codeVarSize + sizeof(code);
		char* payload = malloc(payloadSize);
		bzero(&payload[0], payloadSize);
		strlcpy(&payload[0], extString, stringAllocSize); // insert extString

		intptr_t payloadIntPtr = (intptr_t)payload;
		memcpy((void*)(payloadIntPtr+stringAllocSize), (const void*)&sandbox_extension_consumeAddr, sizeof(uint64_t)); // insert vars

		uint64_t codeStart = stringAllocSize + codeVarSize;
		memcpy((void*)(payloadIntPtr+codeStart), &code[0], sizeof(code)); // insert code

		printf("constructed sandbox_extension_consume payload!\n");

		runPayload(task, (uint8_t*)payload, payloadSize, codeStart, allImageInfoAddr);
		free(payload);
	}
	else
	{
		printf("No Sandbox extension needed, skipping straight to dylib injection...\n");
	}

	// STEP FOUR: load dylib
	size_t stringAllocSize = 256;
	uint64_t codeVarCount = 1;
	uint64_t codeVarSize = codeVarCount * sizeof(uint64_t);

	uint32_t code[3] = {
		// sandbox_extension_consume call
		// arg1: x0, pointer to extension string
		CFSwapInt32(0xC0F7FF10), // adr x0, -0x108 ; reference to dylibPath
		CFSwapInt32(0xA8FFFF58), // ldr x8, -0x0C ; dlopenAddr
		CFSwapInt32(0x00013FD6), // blr x8
	};

	size_t payloadSize = stringAllocSize + codeVarSize + sizeof(code);
	char* payload = malloc(payloadSize);
	bzero(&payload[0], payloadSize);
	strlcpy(&payload[0], dylibPath, stringAllocSize); // insert extString

	intptr_t payloadIntPtr = (intptr_t)payload;
	memcpy((void*)(payloadIntPtr+stringAllocSize), (const void*)&dlopenAddr, sizeof(uint64_t)); // insert vars

	uint64_t codeStart = stringAllocSize + codeVarSize;
	memcpy((void*)(payloadIntPtr+codeStart), &code[0], sizeof(code)); // insert code

	printf("constructed dlopen payload!\n");

	runPayload(task, (uint8_t*)payload, payloadSize, codeStart, allImageInfoAddr);
	free(payload);

	// STEP FIVE: detach from process

	/*ret = ptrace(PT_DETACH, pid, NULL, 0);
	if(ret != KERN_SUCCESS)
	{
		printf("Error detaching from process %d\n", pid);
		return 1;
	}*/

	return 0;
}
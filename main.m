#import <stdio.h>
#import <stdlib.h>
#import <unistd.h>
#import <dlfcn.h>
#import <mach-o/getsect.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/reloc.h>
#import <sys/utsname.h>
#import <string.h>
#import <limits.h>
#import "dyld.h"
#import "sandbox.h"
#import <CoreFoundation/CoreFoundation.h>
#import "shellcode_inject.h"
#import "rop_inject.h"


char* resolvePath(char* pathToResolve)
{
	if(strlen(pathToResolve) == 0) return NULL;
	if(pathToResolve[0] == '/')
	{
		return strdup(pathToResolve);
	}
	else
	{
		char cwd[PATH_MAX];
		if (getcwd(cwd, sizeof(cwd)) == NULL)
		{
			perror("getcwd error");
			return NULL;
		}

		int cwdLen = strlen(cwd);
		int pathToResolveLen = strlen(pathToResolve);
		int resolvedPathLen = cwdLen + strlen(pathToResolve) + 2;
		char* resolvedPath = malloc(resolvedPathLen);
		strncpy(&resolvedPath[0], cwd, cwdLen);
		resolvedPath[cwdLen] = '/';
		strncpy(&resolvedPath[cwdLen+1], &pathToResolve[0], pathToResolveLen);
		resolvedPath[resolvedPathLen] = 0;

		return resolvedPath;
	}
}

int main(int argc, char *argv[], char *envp[]) {
	@autoreleasepool {
		printf("OPAINJECT HERE WE ARE\n");
		printf("RUNNING AS %d\n", getuid());

		if (argc < 3 || argc > 4)
		{
			printf("ERROR: Invalid arguments\n");
			return -1;
		}

		int argOff = 0;

		BOOL isPreflight = argc == 4 && !strcmp(argv[1], "preflight");
		argOff += isPreflight;

		pid_t targetPid = atoi(argv[1+argOff]);
		kern_return_t kret = 0;
		task_t procTask = MACH_PORT_NULL;
		char* dylibPath = resolvePath(argv[2+argOff]);
		if(!dylibPath) return -3;
		if(access(dylibPath, R_OK) < 0)
		{
			printf("ERROR: Can't access passed dylib at %s\n", dylibPath);
			return -4;
		}

		// STEP ONE: get task port
		kret = task_for_pid(mach_task_self(), targetPid, &procTask);
		if(kret != KERN_SUCCESS)
		{
			printf("ERROR: task_for_pid failed with code %d\n", kret);
			return -2;
		}
		if(!MACH_PORT_VALID(procTask))
		{
			printf("ERROR: mach port invalid\n");
			return -3;
		}

		printf("Got task port %d for pid %d!\n", procTask, targetPid);

		// STEP TWO: get aslr slide
		task_dyld_info_data_t dyldInfo;
		uint32_t count = TASK_DYLD_INFO_COUNT;
		task_info(procTask, TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);

		//printImages(procTask, dyldInfo.all_image_info_addr);

		/*char* libName = NULL;
		remoteDlSymFindImage(procTask, dyldInfo.all_image_info_addr, "_pthread_exit", &libName);
		if(libName)
		{
			printf("_pthread_exit in %s\n", libName);
			free(libName);
		}*/

		// STEP THREE : inject
		//injectDylibViaShellcode(procTask, targetPid, dylibPath, dyldInfo.all_image_info_addr);

		int ret = 0;

		if(isPreflight)
		{
			ret = preflightDylibViaRop(procTask, targetPid, dylibPath, dyldInfo.all_image_info_addr);
		}
		else
		{
			injectDylibViaRop(procTask, targetPid, dylibPath, dyldInfo.all_image_info_addr);
		}


		// STEP THREE: Find offsets
		/*vm_address_t dlopenAddr = 0;
		//vm_address_t sandboxExtensionConsumeAddr = 0;


		vm_address_t libDyldAddr = getRemoteImageAddress(procTask, dyldInfo.all_image_info_addr, "/usr/lib/system/libdyld.dylib");
		printf("libDyldAddr: %llX\n", (long long)libDyldAddr);
		if(libDyldAddr)
		{
			dlopenAddr = remoteDlSym(procTask, libDyldAddr, "_dlopen");
		}
		printf("dlopenAddr: %llX\n", (long long)dlopenAddr);

		printImages(procTask, dyldInfo.all_image_info_addr);*/
		



		/*vm_address_t iter = 0;
		while (1)
		{
			//struct mach_header_64 mh = {0};
			vm_address_t addr = iter;
			vm_size_t lsize = 0;
			uint32_t depth;
			//mach_vm_size_t bytes_read = 0;
			struct vm_region_submap_info_64 info;
			mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
			if (vm_region_recurse_64(procTask, &addr, &lsize, &depth, (vm_region_info_t)&info, &count))
			{
				break;
			}
			printf("map 0x%llX, size: %lu, depth: %lu, count: %lu\n", (uint64_t)addr, (unsigned long)lsize, (unsigned long)depth, (unsigned long)count);
			//kr = mach_vm_read_overwrite(targetTask, (mach_vm_address_t)addr, (mach_vm_size_t)sizeof(struct mach_header), (mach_vm_address_t)&mh, &bytes_read);
			//if (kr == KERN_SUCCESS && bytes_read == sizeof(struct mach_header))
			//{

			//}
			iter = addr + lsize;
		}*/

		// STEP THREE, patch sandbox



		// STEP ONE
		// generate sandbox extension and make process consume it by ROPing to sandbox_extension_consume

		// STEP TWO
		// ROP dlopen call

		mach_port_deallocate(mach_task_self(), procTask);
		
		return ret;
	}
}

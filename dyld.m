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
#import <mach-o/dyld_images.h>
#import <sys/utsname.h>
#import <string.h>
#import <limits.h>

#import <CoreFoundation/CoreFoundation.h>

unsigned char* readProcessMemory(task_t t, mach_vm_address_t addr, mach_msg_type_number_t* size)
{
    mach_msg_type_number_t  dataCnt = (mach_msg_type_number_t) *size;
    vm_offset_t readMem = 0;

	kern_return_t kr = vm_read(t, addr, *size, &readMem, &dataCnt);
	if (kr != KERN_SUCCESS)
	{
		return NULL;
	}

    return (unsigned char *)readMem;
}

void iterateImages(task_t task, vm_address_t imageStartPtr, void (^iterateBlock)(char*, struct dyld_image_info*, BOOL*))
{
	mach_msg_type_number_t imageInfosSize = sizeof(struct dyld_all_image_infos);
	struct dyld_all_image_infos* imageInfos = (struct dyld_all_image_infos*)readProcessMemory(task, imageStartPtr, &imageInfosSize);

	if(!imageInfos) return;

	mach_msg_type_number_t infoArraySize = sizeof(struct dyld_image_info) * imageInfos->infoArrayCount;
	struct dyld_image_info* infoArray = (struct dyld_image_info*)readProcessMemory(task, (mach_vm_address_t)imageInfos->infoArray, &infoArraySize);
	if(!infoArray)
	{
		vm_deallocate(mach_task_self(), (vm_address_t)infoArray, infoArraySize);
		return;
	}

	for(int i=0; i < imageInfos->infoArrayCount; i++)
	{
		@autoreleasepool
		{
			mach_msg_type_number_t imagePathSize = PATH_MAX;
			char* itImagePath = (char*)readProcessMemory(task, (mach_vm_address_t)infoArray[i].imageFilePath, &imagePathSize);

			if(itImagePath)
			{
				BOOL stop = NO;
				iterateBlock(itImagePath, &infoArray[i], &stop);
				if(stop) break;
				vm_deallocate(mach_task_self(), (vm_address_t)itImagePath, imagePathSize);
			}
		}
	}

	vm_deallocate(mach_task_self(), (vm_address_t)infoArray, infoArraySize);
	vm_deallocate(mach_task_self(), (vm_address_t)imageInfos, imageInfosSize);
}

vm_address_t getRemoteImageAddress(task_t task, vm_address_t imageStartPtr, const char* imagePath)
{
	__block vm_address_t outAddr = 0;

	iterateImages(task, imageStartPtr, ^(char* iterImagePath, struct dyld_image_info* imageInfo, BOOL* stop)
	{
		if(strcmp(iterImagePath, imagePath) == 0)
		{
			outAddr = (vm_address_t)imageInfo->imageLoadAddress;
		}
	});

	return outAddr;
}

void iterateLoadCommands(task_t task, vm_address_t imageAddress, void (^iterateBlock)(const struct segment_command_64*, vm_address_t, BOOL*))
{
	mach_msg_type_number_t mh_size = sizeof(struct mach_header_64);
	struct mach_header_64* mh = (struct mach_header_64*)readProcessMemory(task, imageAddress, &mh_size);

	vm_address_t addr = (imageAddress + sizeof(struct mach_header_64));
	vm_address_t endAddr = addr + mh->sizeofcmds;

	for(int ci = 0; ci < mh->ncmds && addr <= endAddr; ci++)
	{
		mach_msg_type_number_t cmd_size = sizeof(struct segment_command_64);
		struct segment_command_64* cmd = (struct segment_command_64*)readProcessMemory(task, addr, &cmd_size);
		BOOL stop = NO;
		iterateBlock(cmd, addr, &stop);
		addr = addr + cmd->cmdsize;
		vm_deallocate(mach_task_self(), (vm_address_t)cmd, cmd_size);
		if(stop) break;
	}

	vm_deallocate(mach_task_self(), (vm_address_t)mh, mh_size);
}

void iterateSections(task_t task, vm_address_t commandAddress, const struct segment_command_64* segmentCommand, void (^iterateBlock)(const struct section_64*, BOOL*))
{
	if(segmentCommand->nsects == 0) return;

	vm_address_t startAddr = commandAddress + sizeof(struct segment_command_64);
	mach_msg_type_number_t sectArrSize = sizeof(struct section_64) * segmentCommand->nsects;
	struct section_64* sectArr = (struct section_64*)readProcessMemory(task, startAddr, &sectArrSize);

	for(int i = 0; i < segmentCommand->nsects; i++)
	{
		struct section_64* sect = &sectArr[i];
		BOOL stop;
		iterateBlock(sect, &stop);
		if(stop) break;
	}

	vm_deallocate(mach_task_self(), (vm_address_t)sectArr, sectArrSize);
}

void iterateSymbols(task_t task, vm_address_t imageAddress, void (^iterateBlock)(const char*, const char*, vm_address_t, BOOL*))
{
	__block mach_msg_type_number_t __linkedit_size = sizeof(struct segment_command_64);
	__block mach_msg_type_number_t symtab_cmd_size = sizeof(struct symtab_command);
	__block struct segment_command_64* __linkedit = NULL;
	__block struct symtab_command* symtabCommand = NULL;
	__block mach_msg_type_number_t strtbl_size;

	__block vm_address_t slide;
	__block BOOL firstCmd = YES;

	iterateLoadCommands(task, imageAddress, ^(const struct segment_command_64* cmd, vm_address_t cmdAddr, BOOL* stop)
	{
		if(firstCmd)
		{
			slide = imageAddress - cmd->vmaddr;
			firstCmd = NO;
		}

		switch(cmd->cmd)
		{
			case LC_SYMTAB:
			{
				symtabCommand = (struct symtab_command*)readProcessMemory(task, cmdAddr, &symtab_cmd_size);
				break;
			}

			case LC_SEGMENT_64:
			{
				if (strncmp("__LINKEDIT", cmd->segname, 16) == 0) {
					
					__linkedit = (struct segment_command_64*)readProcessMemory(task, cmdAddr, &__linkedit_size);;
				}
				break;
			}
		}
	});

	if(!__linkedit)
	{
		printf("ERROR: __LINKEDIT not found\n");
		return;
	}
	if(!symtabCommand)
	{
		printf("ERROR: symtab command not found\n");
		return;
	}

	uint64_t fileoff = __linkedit->fileoff;
	uint64_t vmaddr = __linkedit->vmaddr;

	vm_address_t baseAddr = vmaddr + slide - fileoff;
	vm_deallocate(mach_task_self(), (vm_address_t)__linkedit, __linkedit_size);

	vm_address_t strtblAddr = baseAddr + symtabCommand->stroff;
	strtbl_size = symtabCommand->strsize;
	char* strtbl = (char*)readProcessMemory(task, strtblAddr, &strtbl_size);

	vm_address_t lAddr = baseAddr + symtabCommand->symoff;
	for (uint32_t s = 0; s < symtabCommand->nsyms; s++)
	{
		vm_address_t entryAddr = lAddr + sizeof(struct nlist_64) * s;

		mach_msg_type_number_t entry_size = sizeof(struct nlist_64);
		struct nlist_64* entry = (struct nlist_64*)readProcessMemory(task, entryAddr, &entry_size);

		uint32_t off = entry->n_un.n_strx;
		if (off >= strtbl_size || off == 0) {
			vm_deallocate(mach_task_self(), (vm_address_t)entry, entry_size);
			continue;
		}

		const char* sym = &strtbl[off];
		if (sym[0] == '\x00')
		{
			vm_deallocate(mach_task_self(), (vm_address_t)entry, entry_size);
			continue;
		}

		const char* type = NULL;
		switch(entry->n_type & N_TYPE) {
			case N_UNDF: type = "N_UNDF"; break;
			case N_ABS:  type = "N_ABS"; break;
			case N_SECT: type = "N_SECT"; break;
			case N_PBUD: type = "N_PBUD"; break;
			case N_INDR: type = "N_INDR"; break;
		}

		BOOL stop = NO;
		iterateBlock(sym, type, entry->n_value + slide, &stop);
		vm_deallocate(mach_task_self(), (vm_address_t)entry, entry_size);
		if(stop)
		{
			break;
		}
	}

	if(symtabCommand)
	{
		vm_deallocate(mach_task_self(), (vm_address_t)symtabCommand, symtab_cmd_size);
	}
	vm_deallocate(mach_task_self(), (vm_address_t)strtbl, strtbl_size);
}

vm_address_t remoteDlSym(task_t task, vm_address_t imageAddress, const char* symbolName)
{
	__block vm_address_t outAddr = 0;

	iterateSymbols(task, imageAddress, ^(const char* iterSymbolName, const char* type, vm_address_t value, BOOL* stop)
	{
		if(strcmp(type, "N_SECT") == 0)
		{
			if(strcmp(iterSymbolName, symbolName) == 0)
			{
				outAddr = value;
			}
		}
	});

	return outAddr;
}

vm_address_t remoteDlSymFindImage(task_t task, vm_address_t allImageInfoAddr, const char* symbolName, char** imageOut)
{
	__block vm_address_t outAddr = 0;
	__block BOOL* stop1_b;

	iterateImages(task, allImageInfoAddr, ^(char* imageFilePath, struct dyld_image_info* imageInfo, BOOL* stop1)
	{
		stop1_b = stop1;
		iterateSymbols(task, (vm_address_t)imageInfo->imageLoadAddress, ^(const char* iterSymbolName, const char* type, vm_address_t value, BOOL* stop2)
		{
			if(strcmp(type, "N_SECT") == 0)
			{
				if(strcmp(iterSymbolName, symbolName) == 0)
				{
					outAddr = value;
					if(imageOut)
					{
						*imageOut = strdup(imageFilePath);
					}
					*stop2 = YES;
					*stop1_b = YES;
				}
			}
		});
	});
	return outAddr;
}

void printImages(task_t task, vm_address_t imageStartPtr)
{
	iterateImages(task, imageStartPtr, ^(char* imageFilePath, struct dyld_image_info* imageInfo, BOOL* stop)
	{
		printf("Image %s - %llX\n", imageFilePath, (uint64_t)imageInfo->imageLoadAddress);
	});
}

void printSymbols(task_t task, vm_address_t imageAddress)
{
	iterateSymbols(task, imageAddress, ^(const char* iterSymbolName, const char* type, vm_address_t value, BOOL* stop)
	{
		if(strcmp(type, "N_SECT") == 0)
		{
			printf("Symbol %s - %llX\n", iterSymbolName, (uint64_t)value);
		}
	});
}

vm_address_t scanMemory(task_t task, vm_address_t begin, size_t size, char* memory, size_t memorySize, int alignment)
{
	//printf("scanMemory(%llX, %ld)\n", (uint64_t)begin, size);

	mach_msg_type_number_t chunkSize = size;
	if(alignment == 0) alignment = 1;

	unsigned char* buf = readProcessMemory(task, begin, &chunkSize);
	if(!buf || (size != chunkSize))
	{
		printf("[scanMemory] WARNING: Failed to read process memory (%llX, size:%llX)\n", (uint64_t)begin, (uint64_t)size);
		if(buf)
		{
			vm_deallocate(mach_task_self(), (vm_address_t)buf, chunkSize);
		}
		return 0;
	}

	vm_address_t foundMemoryAbsoluteFinal = 0;
	vm_address_t lastFoundMemory = 0;
	while(1)
	{
		unsigned char* foundMemory = memmem(buf + lastFoundMemory, size - lastFoundMemory, memory, memorySize);
		if(foundMemory != NULL)
		{
			lastFoundMemory = foundMemory - buf + memorySize;

			vm_address_t foundMemoryAbsolute = (vm_address_t)(begin + (vm_address_t)(foundMemory - buf));
			//printf("foundMemory absolute: %llX\n", (uint64_t)foundMemoryAbsolute);

			int rest = foundMemoryAbsolute % alignment;
			//printf("rest: %d\n", rest);
			if(rest == 0)
			{
				foundMemoryAbsoluteFinal = foundMemoryAbsolute;
				break;
			}
			continue;
		}
		break;
	}

	vm_deallocate(mach_task_self(), (vm_address_t)buf, chunkSize);
	return foundMemoryAbsoluteFinal;
}

vm_address_t scanTextSegmentForMemory(task_t task, vm_address_t commandAddress, const struct segment_command_64* textCmd, vm_address_t slide, char* memory, size_t memorySize, int alignment)
{
	uint64_t begin = textCmd->vmaddr + slide;
	//printf("- TEXT: %llX -> %llX, %d -\n", begin, begin + textCmd->vmsize, textCmd->nsects);
	vm_address_t mainTextScan = scanMemory(task, begin, textCmd->vmsize, memory, memorySize, alignment);
	if(mainTextScan != 0) return mainTextScan;

	__block vm_address_t sectFound = 0;
	iterateSections(task, commandAddress, textCmd, ^(const struct section_64* sect, BOOL* stop)
	{
		uint64_t sectBegin = sect->addr + slide;
		//printf("-- %s %llX -> %llX --\n", sect->sectname, sectBegin, sectBegin + sect->size);
		if(strcmp(sect->sectname, "__text") == 0)
		{
			vm_address_t subSectScan = scanMemory(task, sectBegin, sect->size, memory, memorySize, alignment);
			if(subSectScan != 0)
			{
				sectFound = subSectScan;
				*stop = YES;
			}
		}
	});
	return sectFound;
}

vm_address_t scanLibrariesForMemory(task_t task, vm_address_t imageStartPtr, char* memory, size_t memorySize, int alignment)
{
	__block vm_address_t foundAddr = 0;

	iterateImages(task, imageStartPtr, ^(char* imageFilePath, struct dyld_image_info* imageInfo, BOOL* stopImages)
	{
		__block vm_address_t slide;
		__block BOOL firstCmd = YES;
		//printf("- iterating %s -\n", imageFilePath);
		iterateLoadCommands(task, (vm_address_t)imageInfo->imageLoadAddress, ^(const struct segment_command_64* cmd, vm_address_t addr, BOOL* stopCommands)
		{
			if(firstCmd)
			{
				slide = (vm_address_t)imageInfo->imageLoadAddress - cmd->vmaddr;
				firstCmd = NO;
			}
			if(cmd->cmd == LC_SEGMENT_64)
			{
				if (strncmp("__TEXT", cmd->segname, 16) == 0)
				{
					vm_address_t addrIfFound = scanTextSegmentForMemory(task, addr, cmd, slide, memory, memorySize, alignment);
					if(addrIfFound != 0)
					{
						foundAddr = addrIfFound;
						*stopCommands = YES;
						*stopImages = YES;
					}
				}
			}
		});
	});

	return foundAddr;
}

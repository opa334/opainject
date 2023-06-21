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
#import "task_utils.h"

#import <CoreFoundation/CoreFoundation.h>

void iterateImages(task_t task, vm_address_t imageStartPtr, void (^iterateBlock)(char*, struct dyld_image_info*, BOOL*))
{
	struct dyld_all_image_infos imageInfos;
	task_read(task, imageStartPtr, &imageInfos, sizeof(imageInfos));

	size_t infoArraySize = sizeof(struct dyld_image_info) * imageInfos.infoArrayCount;
	struct dyld_image_info *infoArray = malloc(infoArraySize);
	task_read(task, (vm_address_t)imageInfos.infoArray, &infoArray[0], infoArraySize);

	for(int i = 0; i < imageInfos.infoArrayCount; i++)
	{
		@autoreleasepool
		{
			char currentImagePath[PATH_MAX];
			if(task_read(task, (vm_address_t)infoArray[i].imageFilePath, &currentImagePath[0], sizeof(currentImagePath)) == KERN_SUCCESS)
			{
				BOOL stop = NO;
				iterateBlock(currentImagePath, &infoArray[i], &stop);
				if(stop) break;
			}
		}
	}
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

void iterateLoadCommands(task_t task, vm_address_t imageAddress, void (^iterateBlock)(const struct load_command* cmd, vm_address_t cmdAddress, BOOL* stop))
{
	struct mach_header_64 mh;
	task_read(task, imageAddress, &mh, sizeof(mh));

	vm_address_t lcStart = (imageAddress + sizeof(struct mach_header_64));
	vm_address_t lcEnd = lcStart + mh.sizeofcmds;

	vm_address_t lcCur = lcStart;
	for(int ci = 0; ci < mh.ncmds && lcCur <= lcEnd; ci++)
	{
		struct load_command loadCommand;
		task_read(task, lcCur, &loadCommand, sizeof(loadCommand));
		BOOL stop = NO;
		iterateBlock(&loadCommand, lcCur, &stop);
		lcCur = lcCur + loadCommand.cmdsize;
		if(stop) break;
	}
}

void iterateSections(task_t task, vm_address_t commandAddress, const struct segment_command_64* segmentCommand, void (^iterateBlock)(const struct section_64*, BOOL*))
{
	if(segmentCommand->nsects == 0) return;

	vm_address_t sectionStart = commandAddress + sizeof(struct segment_command_64);
	for(int i = 0; i < segmentCommand->nsects; i++)
	{
		struct section_64 section = { 0 };
		if (task_read(task, sectionStart + i * sizeof(section), &section, sizeof(section)) == KERN_SUCCESS) {
			BOOL stop;
			iterateBlock(&section, &stop);
			if(stop) break;
		}
	}
}

void iterateSymbols(task_t task, vm_address_t imageAddress, void (^iterateBlock)(const char*, const char*, vm_address_t, BOOL*))
{
	__block struct segment_command_64 __linkedit = { 0 };
	__block struct symtab_command symtabCommand = { 0 };

	__block vm_address_t slide;
	__block BOOL firstSegmentCommand = YES;

	iterateLoadCommands(task, imageAddress, ^(const struct load_command* cmd, vm_address_t cmdAddress, BOOL* stop)
	{
		switch(cmd->cmd)
		{
			case LC_SYMTAB:
			{
				task_read(task, cmdAddress, &symtabCommand, sizeof(symtabCommand));
				break;
			}

			case LC_SEGMENT_64:
			{
				struct segment_command_64 segmentCommand;
				task_read(task, cmdAddress, &segmentCommand, sizeof(segmentCommand));
				if(firstSegmentCommand) {
					slide = imageAddress - segmentCommand.vmaddr;
					firstSegmentCommand = NO;
				}
				if (strncmp("__LINKEDIT", segmentCommand.segname, 16) == 0) {
					__linkedit = segmentCommand;
				}
				break;
			}
		}
	});

	if(__linkedit.cmd != LC_SEGMENT_64)
	{
		printf("ERROR: __LINKEDIT not found\n");
		return;
	}
	if(symtabCommand.cmd != LC_SYMTAB)
	{
		printf("ERROR: symtab command not found\n");
		return;
	}

	uint64_t fileoff = __linkedit.fileoff;
	uint64_t vmaddr = __linkedit.vmaddr;

	vm_address_t baseAddr = vmaddr + slide - fileoff;

	vm_address_t strtblAddr = baseAddr + symtabCommand.stroff;
	size_t strtblSize = symtabCommand.strsize;
	char *strtbl = malloc(strtblSize);
	task_read(task, strtblAddr, &strtbl[0], strtblSize);
	vm_address_t lAddr = baseAddr + symtabCommand.symoff;
	for (uint32_t s = 0; s < symtabCommand.nsyms; s++)
	{
		vm_address_t entryAddr = lAddr + sizeof(struct nlist_64) * s;

		struct nlist_64 entry = { 0 };
		task_read(task, entryAddr, &entry, sizeof(entry));

		uint32_t off = entry.n_un.n_strx;
		if (off >= strtblSize || off == 0) {
			continue;
		}

		const char* sym = &strtbl[off];
		if (sym[0] == '\x00')
		{
			continue;
		}

		const char* type = NULL;
		switch(entry.n_type & N_TYPE) {
			case N_UNDF: type = "N_UNDF"; break;
			case N_ABS:  type = "N_ABS"; break;
			case N_SECT: type = "N_SECT"; break;
			case N_PBUD: type = "N_PBUD"; break;
			case N_INDR: type = "N_INDR"; break;
		}

		BOOL stop = NO;
		iterateBlock(sym, type, entry.n_value + slide, &stop);
		if(stop)
		{
			break;
		}
	}

	free(strtbl);
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

	if(alignment == 0) alignment = 1;

	unsigned char *buf = malloc(size);
	if(task_read(task, begin, &buf[0], size) != KERN_SUCCESS)
	{
		printf("[scanMemory] WARNING: Failed to read process memory (%llX, size:%llX)\n", (uint64_t)begin, (uint64_t)size);
		if(buf) free(buf);
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

	free(buf);
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
		__block BOOL firstSegmentCommand = YES;
		//printf("- iterating %s -\n", imageFilePath);
		iterateLoadCommands(task, (vm_address_t)imageInfo->imageLoadAddress, ^(const struct load_command* cmd, vm_address_t cmdAddress, BOOL* stopCommands)
		{
			if(cmd->cmd == LC_SEGMENT_64)
			{
				struct segment_command_64 segmentCommand = { 0 };
				task_read(task, cmdAddress, &segmentCommand, sizeof(segmentCommand));
				if(firstSegmentCommand)
				{
					slide = (vm_address_t)imageInfo->imageLoadAddress - segmentCommand.vmaddr;
					firstSegmentCommand = NO;
				}
				if (strncmp("__TEXT", segmentCommand.segname, 16) == 0)
				{
					vm_address_t addrIfFound = scanTextSegmentForMemory(task, cmdAddress, &segmentCommand, slide, memory, memorySize, alignment);
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

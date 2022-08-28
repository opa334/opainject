extern vm_address_t getRemoteImageAddress(task_t task, vm_address_t imageStartPtr, const char* imageName);
extern vm_address_t remoteDlSym(task_t task, vm_address_t imageStartPtr, const char* symbolName);
extern vm_address_t remoteDlSymFindImage(task_t task, vm_address_t allImageInfoAddr, const char* symbolName, char** imageOut);

extern void printImages(task_t task, vm_address_t imageStartPtr);
extern void printSymbols(task_t task, vm_address_t imageAddress);
extern vm_address_t scanLibrariesForMemory(task_t task, vm_address_t imageStartPtr, char* memory, size_t memorySize, int alignment);
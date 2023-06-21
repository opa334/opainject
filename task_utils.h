kern_return_t task_read(task_t task, vm_address_t address, void *outBuf, vm_size_t size);
char *task_copy_string(task_t task, vm_address_t address);
kern_return_t task_write(task_t task, vm_address_t address, void* inBuf, vm_size_t size);
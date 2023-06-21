# opainject

iOS tool to inject a dylib into a process using both shellcode and ROP methods. (By default ROP method is used, it's superior to the shellcode method in every way but I started with the shellcode method and decided to leave it in).

Tested on iOS 14, 15, 16 and 17. Should theoretically work on 11.0 and up. On arm64e devices the dylib will inject but crash the process if it's not in Trust Cache.
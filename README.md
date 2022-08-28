# opainject

iOS tool to inject a dylib into a process using both shellcode and ROP methods.

Tested on iOS 14 and 15 (yes you heard that right, but this is actually useless without some sort of PMAP trust level bypass as the dylib will just be mapped as R-- and the process will crash).

I published this without cleaning up much... Some stuff (e.g. what I called "preflighting" in the code) is actually completely useless.
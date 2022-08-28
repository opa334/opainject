# opainject

iOS tool to inject a dylib into a process using both shellcode and ROP methods. (By default ROP method is used, it's superior to the shellcode method in every way but I started with the shellcode method and decided to leave it in).

Tested on iOS 14 and 15 (yes you heard that right, but this is actually useless without some sort of PMAP trust level bypass as the dylib will just be mapped as R-- and the process will crash).

On PAC devices, this needs a userland PAC bypass to work, this tool only works if the PAC keys (jop_pid, rop_pid) of the opainject process and the process it should inject into are the same. Jailbreaks should already handle this (at least Taurine does).

I published this without cleaning up much... Some stuff (e.g. what I called "preflighting" in the code) is actually completely useless.
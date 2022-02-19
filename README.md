<h1 align="center"> Bare Metal Jacket </h1> <br>
<p align="center">
  <a>
    <img src="BMJ.png" width="450">
  </a>
</p>


## Introduction

BMJ contains low-level code fragments (in a form of NASM macros) that can assist in writing small, position-independent and null-free shellcode. Most of the macros communicate directly with the kernel - no external dependencies (such as glibc) are needed, so the code is portable across all 64-bit GNU/Linux systems.

## Features
The framework's source is divided into 16 separate sections - each of them provides different set of macros for specific tasks.

* [ 0x01 ] --- > Stack/register/string allocation helpers (variable initialization, XOR/PUSH chaining)
* [ 0x02 ] --- > Auxiliary macros (stack operations, relative addressing, data types operations)           
* [ 0x03 ] --- > VM/debugging detection (RDTSC, number of CPU cores, file age, clock accelleration mechanism)
* [ 0x04 ] --- > Time-specific operations (time locks, timers, seeders               
* [ 0x05 ] --- > Coprocessing (forking, synchronised execution, standard filesystem mutexes, daemonization)
* [ 0x06 ] --- > IPC communication (signal handling/blocking/disposition/delivery)
* [ 0x07 ] --- > Low-level socket operations (TCP/UDP sock initialization, port binding, listeners) 
* [ 0x08 ] --- > High-level socket operations (reverse/bind shells with auth, file exfiltration)             
* [ 0x09 ] --- > Reverse TCP stagers (LKM/file/buffer retrieval)              
* [ 0x10 ] --- > Operations on files and file descriptors (reading, writing, closing, executing, mapping files)            
* [ 0x11 ] --- > Position-aware macros (section/relative label calculations)
* [ 0x12 ] --- > Administration, environment mapping (privilleges detection/elevation, power management,     crawling,process priority, shell invocation)
* [ 0x13 ] --- > Command execution
* [ 0x14 ] --- > Size padders (NOP sleds, pattern/byte fill)
* [ 0x15 ] --- > Disablers (security measures, ASLR, process inspection)
* [ < * > ] --- > Experimental code (network/signal-based c2 channels, process protection, signal throwback) 

## Examples
  `cmd_exec.asm` - Checks for elevated privilleges. If present, a command is executed in background and the machine is rebooted afterwards.
  
  `timed_stager.asm` - A program with operational time of 5 minutes attempts to download a remote file and execute it in memory. A TCP reconnection in case of failure is performed in background every 20 seconds, infinitely.

  `reverse_shell.asm` - A reverse shell that removes itself via `argv[0]` unlink, changes it's process priority, elevates privilleges and detaches from current terminal session.

  `vm_and_stuff.asm` - A program prepended with 40 nop (`0x90`) instructions, padded with nops until it reaches 256 bytes in size. Only one instance can run simultaneously on host, thanks to `flock(2)`. After checking for VM presence and an attempt to disable ASLR, a TCP-connect pingback payload is launched.
## License
This software is under [MIT License](https://en.wikipedia.org/wiki/MIT_License)



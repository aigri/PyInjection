# PyInjection

Python script who inject code in binary (It should not be protected by PIE)

## How does it work ?

### Searching for "LOAD" segments
This will look for if the program contains two LOAD segments (which have the flag "RWX")

### Injecting code
Before we need to xor each registry in order to clean the stackframe
Now we can take advantage of the free space between the two segments to inject our code that can be executed with the 'X' flag of the segments.

### Patching Entry Point
Once the code has been injected, it is necessary to change the entrypoint and put it on the start address of the code so that the execution goes through it.

### Jumping on OEP
Then you just have to add an instruction (like ``mov ebp, oep_addr; jmp ebp``)at the end of the code to be injected which will take care of jumping on the old entry point (which can be located at the address pointed by the e_entry member in the ELF32 header) so that the program resumes the course of its execution.

### Why it should not be protected with PIE ?

It shouldn't because PIE is used to randomize the addresses of the different segments and so on.
So if the address of the "LOAD" segments is changed at each execution it becomes complicated to predict where the code can be injected.

### Explanatory diagram
<img src="/src/a.jpeg">

## PoC
Little Proof Of Concept of this script

<img src="/src/PoC.gif">

## Greetz

Thanks to @nqntmqmqmb who helped me a lot





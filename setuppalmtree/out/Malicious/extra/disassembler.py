import os
from capstone import *
from capstone.x86 import *
import pefile
import multiprocessing
from math import ceil
files = []
benign=False
numberofthreads=4

def insertstarspaces(line):
    l=0
    while(l<len(line)):
        if(line[l]=="*"):
            line=line[:l]+ " * " + line[l+1:]
            l+=2
        l = l+1
    return line

def insertspaces(string):
    i = 0
    while(i < len(string)):
        if(string[i]=="["):
            if(string[i-1]!=" "):
                string=string[:i]+" "+string[i:]
            else:    
                string=string[:i+1]+" "+string[i+1:]
        elif(string[i]=="]"):
            if(string[i-1]!=" "):
                if(len(string)>i+1):
                    flag = True if string[i+1]!=" " else False
                    string=string[:i]+" "+string[i:]
                    if(flag==False):
                        i+=1
                else:
                    string=string[:i]+" "+string[i:]
                    i+=1
            else:
                string=string[:i+1]+" "+string[i+1:]
        i+=1
    return string

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
def fine_disassemble(exe,filename):
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
            if(stringobject.find("[")!=-1 or stringobject.find("]")!=-1):
                stringobject=insertspaces(stringobject)
            if(stringobject.find("*")!=-1):
                stringobject=insertstarspaces(stringobject)
            if(benign==True):
                with open("out/Benigns/"+filename+".text","a") as out:
                    out.write(stringobject)
                    out.write("\n")
            else:
                with open("out/"+filename+".text","a") as out:
                    out.write(stringobject)
                    out.write("\n")
            last_address = int(i.address)
            last_size = i.size
        #sometimes you need to skip some bytes
        begin = max(int(last_address),begin)+last_size+1
        if begin >= end:
            print("out")
            break
#generate the binary codes and write the disassembly to a file:
def threadingtask(list):
    #disassembly and file writing:
    for f in list:
        if(benign==True):
            exe_file_path = "programs/Benigns/"+f
        else:
            exe_file_path = f
        print(f)
        try:
        #parse exe file
            exe = pefile.PE(exe_file_path)
            try:
        #call the function I created earlier
                fine_disassemble(exe,f)
            except:
                print('something is wrong with this exe file')
        except:
            print('pefile cannot parse this file')


if __name__ =="__main__":
    #fetch all the files in the directory:
    if(benign==True):
        for file in os.listdir("programs/Benigns/"):
            if file[-4:]==".exe" or file[-4:]==".EXE":
                files.append(file)
            else:
                continue
    else:
        for file in os.listdir():
            if file[:5]=="Virus":
                files.append(file)
            else:
                continue
    print(files)
    print(len(files))
    #split list in 4 parts
    chunked_list=list()
    chunksize=ceil(len(files)/numberofthreads)
    for i in range(0,len(files),chunksize):
        if(i+chunksize<len(files)):
            chunked_list.append(files[i:i+chunksize])
        else:
            chunked_list.append(files[i:len(files)])
    print(chunked_list)
    print(len(chunked_list))

    processes = []
    for s in range(numberofthreads):
        process = multiprocessing.Process(target=threadingtask, args=(chunked_list[s],))
        processes.append(process)

    for k in processes:
        k.start()

    for m in processes:
        m.join()
        
    print("Done!")
import os
from capstone import *
from capstone.x86 import *
from math import ceil
import multiprocessing

numberofthreads=4
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

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




def threading(f): 
    for file in f: 
        with open(file,"rb") as inp:
            text = inp.read()
            for i in md.disasm(text,0x1000):
                stringobject = "%s %s" %(i.mnemonic, i.op_str)
                stringobject=stringobject.replace(',','')
                if(stringobject.find("[")!=-1 or stringobject.find("]")!=-1):
                    stringobject=insertspaces(stringobject)
                if(stringobject.find("*")!=-1):
                    stringobject=insertstarspaces(stringobject)

                with open("out/"+str(file)+".text","a") as out:
                        out.write(stringobject)
                        out.write("\n")

if __name__ =="__main__":

    files = []
    for file in os.listdir(): 
        if(file[:5]=="Virus"):
            files.append(file)

    chunked_list=list()
    chunksize=ceil(len(files)/numberofthreads)
    for i in range(0,len(files),chunksize):
        if(i+chunksize<len(files)):
            chunked_list.append(files[i:i+chunksize])
        else:
            chunked_list.append(files[i:len(files)])

    processes = []
    
    for s in range(len(chunked_list)):
        process = multiprocessing.Process(target=threading, args=(chunked_list[s],))
        processes.append(process)

    for k in processes:
        k.start()

    for m in processes:
        m.join()
        
    print("Done!")
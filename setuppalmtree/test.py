import os 
import multiprocessing
from math import ceil

numberofthreads=4

def insertstarspaces(line):
    l=0
    while(l<len(line)):
        if(line[l]=="*"):
            line=line[:l]+ " * " + line[l+1:]
            l+=2
        l = l+1
    return line

files=[]
for file in os.listdir():
    if(file[-5:]==".text"):
        files.append(file)

def linewriter(filearray):
    lines=[]
    for fi in filearray: 
        with open(fi,"r") as inp:
            for line in inp.readlines():
                lines.append(line)
        index=0
        while(index < len(lines)):
            if(lines[index].find("*")!=-1):
                lines[index]=insertspaces(lines[index])
            index+=1
        with open(fi,"w") as out:
            for text in lines: 
                out.write(text)

if __name__ =="__main__":
    #split list in numberofthreads parts
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
        process = multiprocessing.Process(target=linewriter, args=(chunked_list[s],))
        processes.append(process)

    for k in processes:
        k.start()

    for m in processes:
        m.join()
        
    print("Done!")
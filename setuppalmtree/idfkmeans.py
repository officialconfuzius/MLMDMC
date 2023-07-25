import pandas as pd
import os

filelist = []
viruscount = 0
backdoorcount = 0
trojancount = 0
wormcount = 0

idf = {"name":[],"document_frequency":[]}
def recognizeinst(assemblyline): 
    index = 0
    while(index < len(assemblyline)):
        instr="" 
        if(assemblyline[index] == " "): 
            i2 = 0
            while(i2 < index):
                instr=instr+assemblyline[i2]
                i2+=1
            return instr
        index+=1
    return None

def mainmethod(filelist): 
    for file in filelist: 
        alreadyadded = {}
        try: 
            with open("out/Malicious/"+str(file),"r") as inp: 
                for line in inp.readlines(): 
                    instrname=recognizeinst(line)
                    if(instrname not in idf["name"]):
                        idf["name"].append(instrname)
                        idf["document_frequency"].append(1)
                        alreadyadded[instrname]=1
                    else: 
                        if(instrname in alreadyadded.keys()):
                            continue
                        else:
                            idf["document_frequency"][idf["name"].index(instrname)] = idf["document_frequency"][idf["name"].index(instrname)]+1
                            alreadyadded[instrname]=1
        except: 
            with open("out/"+str(file),"r") as inp: 
                for line in inp.readlines(): 
                    instrname=recognizeinst(line)
                    if(instrname not in idf["name"]):
                        idf["name"].append(instrname)
                        idf["document_frequency"].append(1)
                        alreadyadded[instrname]=1
                    else: 
                        if(instrname in alreadyadded.keys()):
                            continue
                        else:
                            idf["document_frequency"][idf["name"].index(instrname)] = idf["document_frequency"][idf["name"].index(instrname)]+1
                            alreadyadded[instrname]=1

def findMalwareType(filename):
    if(filename.find("virus")!=-1 or filename.find("Virus")!=-1):
        return 1
    elif(filename.find("Backdoor")!=-1 or filename.find("backdoor")!=-1):
        return 2
    elif(filename.find("Worm")!=-1 or filename.find("worm")!=-1):
        return 3
    elif(filename.find("Trojan")!=-1 or filename.find("trojan")!=-1):
        return 4
    elif(filename.find("Exploit")!=-1 or filename.find("exploit")!=-1):
        return 5
    elif(filename.find("Hoax")!=-1 or filename.find("hoax")!=-1):
        return 6
    elif(filename.find("DoS")!=-1 or filename.find("dos")!=-1):
        return 7
    elif(filename.find("Flooder")!=-1 or filename.find("flooder")!=-1):
        return 8
    elif(filename.find("Rootkit")!=-1 or filename.find("rootkit")!=-1):
        return 9
    elif(filename.find("Backdoor")!=-1 or filename.find("backdoor")!=-1):
        return 10
    elif(filename.find("SpamTool")!=-1 or filename.find("spamtool")!=-1):
        return 11
    elif(filename.find("Spoofer")!=-1 or filename.find("spoofer")!=-1):
        return 12
    elif(filename.find("Packed")!=-1 or filename.find("packed")!=-1):
        return 13
    else:
        #return 14 if malware cannot be matched
        return 14

for file in os.listdir("out/Malicious/"): 
    if(file[-5:]==".text"):
        if findMalwareType(file) == 1 and viruscount < 354: 
            viruscount+=1
            filelist.append(file)
        elif findMalwareType(file) == 2 and backdoorcount < 354: 
            backdoorcount+=1
            filelist.append(file)
        elif findMalwareType(file) == 3 and wormcount < 354: 
            wormcount+=1
            filelist.append(file)
        elif findMalwareType(file) == 4 and trojancount < 354: 
            trojancount+=1
            filelist.append(file) 
filelist.append("putty.exe.text")
filelist.append("infectputty.exe.text")
mainmethod(filelist)
print("Done!")
df = pd.DataFrame(idf)
df.to_csv("out/idfscoresdown.csv")
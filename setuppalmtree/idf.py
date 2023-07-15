import pandas as pd
import os
from threading import *

numberofthreads=4

idf = {"name":[],"document_frequency":[]}

#this one has to be copied to embeddings.py
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

def readfiles(path):
    files=[]
    for file in os.listdir(path): 
        if(file[-5:]==".text"):
            files.append(file)
    return files

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
            try:
                with open("out/Benigns/"+str(file),"r") as inp: 
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
                                idf["document_frequency"][idf["name"].index(instrname)]=idf["document_frequency"][idf["name"].index(instrname)]+1
                                alreadyadded[instrname]=1
            except: 
                with open("out/Malicious/extra/out/"+str(file),"r") as inp: 
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
                                idf["document_frequency"][idf["name"].index(instrname)]=idf["document_frequency"][idf["name"].index(instrname)]+1
                                alreadyadded[instrname]=1

#create array of all files
allfiles = readfiles("out/Malicious/")
allbenigns = readfiles("out/Benigns/")
allextra  = readfiles("out/Malicious/extra/out/")
for a in allbenigns: 
    allfiles.append(a)

for extra in allextra: 
    allfiles.append(extra)

mainmethod(allfiles)
print("Done!")
df = pd.DataFrame(idf)
df.to_csv("out/idfscores.csv")
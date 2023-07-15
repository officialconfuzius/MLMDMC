import os
from config import *
from torch import nn
from scipy.ndimage.filters import gaussian_filter1d
from torch.autograd import Variable
import numpy as np
import eval_utils as utils
import csv
import pandas as pd
import math


palmtree = utils.UsableTransformer(model_path="./palmtree/transformer.ep19", vocab_path="./palmtree/vocab")
files=[]
benign=False
sumofallscores=0
df = pd.read_csv("out/idfscores.csv")

def findMalwareType(filename):
    if(benign):
        return 0
    elif(filename.find("virus")!=-1 or filename.find("Virus")!=-1):
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
if(benign==True):
    for f in os.listdir("out/Benigns/"):
        if(f[-5:]==".text"):
            files.append(f)
        else:
            continue
else:
    for f in os.listdir("out/Malicious/"):
        if(f[-5:]==".text"):
            files.append(f)
        else:
            continue
    for h in os.listdir("out/Malicious/extra/out/"):
        if(h[-5:]==".text"):
            files.append(h)
        else:
            continue

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

def getNumberOfDocuments():
    number=0
    ar1=readfiles("out/Malicious/")
    ar2=readfiles("out/Benigns/")
    ar3=readfiles("out/Malicious/extra/out/")
    number=len(ar1)+len(ar2)+len(ar3)
    return number

def readfiles(path):
    files=[]
    for file in os.listdir(path): 
        if(file[-5:]==".text"):
            files.append(file)
    return files

def generatefrequencies(instructions): 
    dict = {}
    for inst in instructions: 
        instruction = recognizeinst(inst)
        if (instruction in dict.keys()):
            dict[instruction]=dict[instruction]+1
        else: 
            dict[instruction]=1
    return dict

def generatescores(instructions,dict):
    global sumofallscores
    re = []
    numberofdocs=getNumberOfDocuments()
    for inst in instructions: 
        instru=recognizeinst(inst)
        docfreq=df["document_frequency"].values[np.where(df["name"].values==instru)[0][0]]
        tf=(1+math.log10(dict[instru]))/(1+math.log10(max(dict.values())))
        tfidfscore=math.log10(numberofdocs/docfreq)*tf
        if tfidfscore!=0.0:
            sumofallscores = sumofallscores + tfidfscore
        re.append(tfidfscore)
    return re

def minimizearray(array,tfidfar):
    i = 0
    while (i < len(array)): 
        if(tfidfar[i]==0.0): 
            array.pop(i)
            tfidfar.pop(i)
            continue
        else:
            i+=1
    return array

def createEmbeddings(inp,filename):
    text=[]
    malwaretype=findMalwareType(filename)
    #read one program as input and add it to the assembly text array
    with open(inp,"r") as input:
        for texti in input.readlines():
            texti=texti[:-1]
            text.append(texti)
    i=0
    #generate dictionary for all tf scores: 
    frequencies = generatefrequencies(text)
    #adjust the length of the input read
    length=1000
    ar=[]
    program2vec=np.zeros(128)
    while(i<len(text)):
        if(i+length<len(text)):
            for l in range(0,length):
                ar.append(text[i])
                i+=1
        else:
            while(i < len(text)):
                ar.append(text[i])
                i+=1
        #generate all tf-idf scores for ar array
        tfidf=generatescores(ar,frequencies)
        #reduce computation effort
        ar = minimizearray(ar,tfidf)
        #generate the embeddings based on assembly array
        if(len(ar)>0):
            embeddings = palmtree.encode(ar)
            # uncomment for old implementation
            # for embedding in embeddings:
            iterator=0
            while iterator < len(embeddings):
                #tf-idf implmementation
                embeddings[iterator]=np.multiply(embeddings[iterator],tfidf[iterator])
                #add the vector to the numpy array
                program2vec=np.add(program2vec,embeddings[iterator])
                iterator+=1
            ar.clear()
    program2vec=np.divide(program2vec,sumofallscores)
    print(program2vec)
    if(benign==True):
        with open("out/Benigns/out/benignembeddings.csv", "a") as output: 
            writer=csv.writer(output)
            output.write(str(malwaretype)+",0,")
            writer.writerow(program2vec)
    else:
        with open("out/Malicious/out/maliciousembeddings.csv", "a") as output:
            writer=csv.writer(output)
            output.write(str(malwaretype)+",1,")
            writer.writerow(program2vec)

for file in files:
    print(file)
    if(benign==True):
        createEmbeddings("out/Benigns/"+str(file),str(file))
    else:
        if(file[:11]!="VirusShare_"):
            createEmbeddings("out/Malicious/"+str(file),str(file))
        else:
            createEmbeddings("out/Malicious/extra/out/"+str(file),str(file))

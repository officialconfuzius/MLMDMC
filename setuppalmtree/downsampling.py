import os
import numpy as np
import csv
import eval_utils as utils
from config import *
from torch import nn
from scipy.ndimage.filters import gaussian_filter1d
from torch.autograd import Variable
import math
import pandas as pd

sumofallscores=0
df = pd.read_csv("out/idfscoresdown.csv")
tfidf = False

palmtree = utils.UsableTransformer(model_path="./palmtree/transformer.ep19", vocab_path="./palmtree/vocab")

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
def getNumberOfDocuments():
    number=1416
    return number

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


def createtfidfEmbeddings(inp,filename):
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
    with open("out/Malicious/out/maliciousembeddingstfidf.csv", "a") as output:
        writer=csv.writer(output)
        output.write(str(malwaretype)+",1,")
        writer.writerow(program2vec)

def createEmbeddings(inp,filename):
    text=[]
    malwaretype=findMalwareType(filename)
    if malwaretype!=0:
        #read one program as input and add it to the assembly text array
        with open(inp,"r") as input:
            for texti in input.readlines():
                texti=texti[:-1]
                text.append(texti)
        i=0
        #adjust the length of the input read
        length=1000
        ar=[]
        program2vec=np.zeros(128)
        test=0.0
        while(i<len(text)):
            if(i+length<len(text)):
                for l in range(0,length):
                    ar.append(text[i])
                    i+=1
            else:
                while(i < len(text)):
                    ar.append(text[i])
                    i+=1
            #generate the embeddings based on assembly array
            embeddings = palmtree.encode(ar)
            for embedding in embeddings:
                test+=embedding[0]
                #add the vector to the numpy array
                program2vec=np.add(program2vec,embedding)
            print(embeddings.shape)
            ar.clear()
        program2vec=np.divide(program2vec,len(text))
        print(program2vec)
        print(program2vec.shape)
        
        with open("out/Malicious/out/maliciousembeddingsam.csv", "a") as output:
            writer=csv.writer(output)
            output.write(str(malwaretype)+",1,")
            writer.writerow(program2vec)

def generateEmbedding(file): 
    if tfidf == False: 
        createEmbeddings("out/Malicious/"+str(file),str(file))
    else: 
        createtfidfEmbeddings("out/Malicious/"+str(file),str(file))



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
    
viruscount = 0
backdoorcount = 0
trojancount = 0
wormcount = 0
for file in os.listdir("out/Malicious/"): 
    if(file[-5:]==".text"):
        if findMalwareType(file) == 1 and viruscount < 354: 
            viruscount+=1
            generateEmbedding(file)
        elif findMalwareType(file) == 2 and backdoorcount < 354: 
            backdoorcount+=1
            generateEmbedding(file)
        elif findMalwareType(file) == 3 and wormcount < 354: 
            wormcount+=1
            generateEmbedding(file)
        elif findMalwareType(file) == 4 and trojancount < 354: 
            trojancount+=1
            generateEmbedding(file)
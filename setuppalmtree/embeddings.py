import os
from config import *
from torch import nn
from scipy.ndimage.filters import gaussian_filter1d
from torch.autograd import Variable
import numpy as np
import eval_utils as utils
import csv


palmtree = utils.UsableTransformer(model_path="./palmtree/transformer.ep19", vocab_path="./palmtree/vocab")
files=[]
benign=False

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
        return 0
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

def createEmbeddings(inp,filename):
    text=[]
    malwaretype=findMalwareType(filename)
    if((benign==False and malwaretype!=0) or benign):
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
        createEmbeddings("out/Malicious/"+str(file),str(file))

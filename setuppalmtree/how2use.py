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
            writer.writerow(program2vec)
    else:
        with open("out/Malicious/out/maliciousembeddings.csv", "a") as output:
            writer=csv.writer(output)
            output.write("malwaretype,")
            writer.writerow(program2vec)

for file in files:
    print(file)
    if(benign==True):
        createEmbeddings("out/Benigns/"+str(file),str(file))
    else:
        createEmbeddings("out/Malicious/"+str(file),str(file))

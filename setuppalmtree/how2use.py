import os
from config import *
from torch import nn
from scipy.ndimage.filters import gaussian_filter1d
from torch.autograd import Variable
import torch
import numpy as np
import eval_utils as utils


palmtree = utils.UsableTransformer(model_path="./palmtree/transformer.ep19", vocab_path="./palmtree/vocab")
files=[]
for f in os.listdir():
    if(f[-5:]==".text"):
        files.append(f)
    else:
        continue

def createEmbeddings(inp):
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
            #write the file
            # with open("out/"+inp+".output","a") as out:
            #     out.write(str(embedding))
            #     out.write("\n")
            #add the vector to the numpy array
            program2vec=np.add(program2vec,embedding)
        print(embeddings.shape)
        ar.clear()
    print(program2vec)
    test=test/len(text)
    program2vec=np.divide(program2vec,len(text))
    print(program2vec)
    print(program2vec.shape)
    print(test)

for file in files:
    createEmbeddings(str(file))

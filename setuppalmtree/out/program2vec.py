import numpy as np
import pandas as pd
import os
files=[]
embeddings=[]
for file in os.listdir():
    if(file[-7:]==".output"):
        files.append(file)
    else:
        continue

# #read the output file
# for f in files:
#     embeddings = np.array([],[])
#     with open(f,"r"):


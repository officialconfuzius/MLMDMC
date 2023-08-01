import pandas as pd
from imblearn.over_sampling import ADASYN
from collections import Counter
import csv
#create adasyn module
ada = ADASYN()
#import original features
dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
df = pd.concat([dfb,dfm])
#y denotes labels, X denotes embeddings
y=df.iloc[:,1].values
X=df.iloc[:,2:].values
#apply adasyn to original features
X,y = ada.fit_resample(X,y)
#the new resulting structure of the dataset is printed
print(Counter(y))

#write the output: 
i = 0
while i < len(X): 
    with open("out/oversamplingstfidf.csv", "a") as out: 
        writer = csv.writer(out)
        out.write(str(y[i])+",")
        writer.writerow(X[i])
    i+=1
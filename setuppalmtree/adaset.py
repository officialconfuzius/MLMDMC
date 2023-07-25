import pandas as pd
from imblearn.over_sampling import ADASYN
from collections import Counter
import csv
ada = ADASYN()
dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
df = pd.concat([dfb,dfm])
y=df.iloc[:,1].values
X=df.iloc[:,2:].values
X,y = ada.fit_resample(X,y)
print(Counter(y))

#output: 
i = 0
while i < len(X): 
    with open("out/oversamplingstfidf.csv", "a") as out: 
        writer = csv.writer(out)
        out.write(str(y[i])+",")
        writer.writerow(X[i])
    i+=1
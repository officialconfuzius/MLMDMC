import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn import metrics
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, f1_score, precision_score, recall_score)
from sklearn.model_selection import StratifiedKFold, GridSearchCV, RandomizedSearchCV, cross_val_score
from hyperopt import tpe, STATUS_OK, Trials, hp, fmin, space_eval
from sklearn.svm import SVC
from math import sqrt

#for oversampled data: 
df = pd.read_csv("../setuppalmtree/out/oversamplingstfidf.csv")

# dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
# dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
# df = pd.concat([dfb,dfm])

#for oversampled data: 
y = df.iloc[:,0].values
X= df.iloc[:,1:].values
# y=df.iloc[:,1].values
# X=df.iloc[:,2:].values

#load the gold standard
putty = np.load("out/putty.exe.textEXTENDED.npy")
maliciousputty = np.load("out/infectputty.exe.textEXTENDED.npy")
array = [putty, maliciousputty]

#standardize the data
sc=StandardScaler()
X_train = sc.fit_transform(X)
array = sc.fit_transform(array)

#this new configuration has an accuracy of .6191 on the testing set tf-idf
# svc=SVC(C=10.0,gamma=10.0,kernel='poly')
#this configuration has an accuracy of .8837
# svc=SVC(gamma=0.1,C=10.0,kernel='rbf')
#this configuration has an accuracy of .8739 embeddings mean choice
# svc=SVC(gamma=0.1,C=1.0,kernel="rbf")
# extended tf-idf configuration accuracy: .5888
svc=SVC(C=10.0,gamma=10.0,kernel="rbf")
# configuration for extended arithmetic mean: .9261
# svc=SVC(C=10.0,gamma=0.1,kernel="rbf")
# svc = SVC()

svc.fit(X,y)
#predict the gold standard
array = svc.predict(array)

puttyprediction = array[0]
maliciousputtyprediction = array[1]
#print the results
print("Putty (expected 0): "+str(puttyprediction))
print("MaliciousPutty (expected 1): "+str(maliciousputtyprediction))
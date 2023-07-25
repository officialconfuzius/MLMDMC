import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score,
    recall_score,
    f1_score, accuracy_score,confusion_matrix,ConfusionMatrixDisplay)
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV, RandomizedSearchCV, cross_val_score,validation_curve
from scipy.stats import randint
from math import sqrt
from sklearn.ensemble import RandomForestClassifier

#for oversampled data: 
df = pd.read_csv("../setuppalmtree/out/oversamplingsam.csv")

# dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
# dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
# df = pd.concat([dfb,dfm])

#for oversampled data: 
y = df.iloc[:,0].values
X= df.iloc[:,1:].values
# y=df.iloc[:,1].values
# X=df.iloc[:,2:].values

putty = np.load("out/putty.exe.textAM.npy")
maliciousputty = np.load("out/infectputty.exe.textAM.npy")

array = [putty, maliciousputty]

sc=StandardScaler()
X_train = sc.fit_transform(X)
array = sc.fit_transform(array)
#CLASSIFIERS
#this model has an accuracy of .9111 on testing set of extended arithemetic mean: 
model = RandomForestClassifier(max_depth=30,min_samples_leaf=1,min_samples_split=2,n_estimators=800)
#this model has an accuracy of .5202 on the testing set tf-idf
# model = RandomForestClassifier(max_depth=30,min_samples_leaf=1,min_samples_split=5,n_estimators=1200)
#this model has an accuracy of .8697
# model = RandomForestClassifier(n_estimators=1200,max_depth=25,min_samples_leaf=1,min_samples_split=2, criterion='entropy',random_state=0)
#this model is even better accuracy of .8717 embeddings mean choice
# model = RandomForestClassifier(max_depth= 30, min_samples_leaf= 1, min_samples_split=2, n_estimators= 1300, criterion='entropy',random_state=0)
# configuration for tf-idf extended accuracy of .6735
# model = RandomForestClassifier(max_depth=30,min_samples_leaf=1,min_samples_split=2,n_estimators=500)
model.fit(X,y)

array = model.predict(array)
puttyprediction = array[0]
maliciousputtyprediction = array[1]

print("Putty (expected 0): "+str(puttyprediction))
print("MaliciousPutty (expected 1): "+str(maliciousputtyprediction))
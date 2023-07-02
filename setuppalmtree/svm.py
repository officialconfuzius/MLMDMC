import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

df = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)

df[0] = df[0].replace(["malwaretype"],0)
df[0] = df[0].replace(["test"],1)

y_train=df.iloc[:,0]
X_train=df.iloc[:,1:]

# X_train,y_train,X_test,y_test=train_test_split(X,y,test_size=0.25,random_state=0)

# sc=StandardScaler()
# X_train = sc.fit_transform(X_train)
# X_test = sc.fit_transform(X_test)

svm = SVC(kernel='rbf',random_state=0)
svm.fit(X_train,y_train)

print(svm.score(X_train,y_train))
# print(svm.score(X_test,y_test))
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
#THIS IMPLEMENTATION STILL LACKS ON HYPERPARAMETER TUNING
#THIS HAS TO BE CHANGED LATER ON:
df = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
#ignore first column for training data and ignore all columns but the first
#one for the class
#THE CLASS IS STILL MALWARETYPE, BUT IT SHOULD BE CHANGED IN THE FUTURE TO MALWARE
y_train=df.iloc[:,0]
X_train=df.iloc[:,1:]

print(X_train)
print(y_train)

#CLASSIFIERS
model = RandomForestClassifier(n_estimators=100, criterion='entropy',random_state=0)
model.fit(X_train,y_train)
print(model.score(X_train,y_train))
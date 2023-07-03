import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV, RandomizedSearchCV, cross_val_score

from sklearn.ensemble import RandomForestClassifier
#THIS IMPLEMENTATION STILL LACKS ON HYPERPARAMETER TUNING
#THIS HAS TO BE CHANGED LATER ON:
dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
df = pd.concat([dfb,dfm])
#ignore first column for training data and ignore all columns but the first
#one for the class
#THE CLASS IS STILL MALWARETYPE, BUT IT SHOULD BE CHANGED IN THE FUTURE TO MALWARE
y=df.iloc[:,1].values
X=df.iloc[:,2:].values

X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=0)

sc=StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.fit_transform(X_test)

#CLASSIFIERS
model = RandomForestClassifier(n_estimators=100, criterion='entropy',random_state=0)

#HYPERPARAMETER OPTIMIZATION
#GridSearch
n_estimators = [100, 300, 500, 800, 1200]
max_depth = [5, 8, 15, 25, 30]
min_samples_split = [2, 5, 10, 15, 100]
min_samples_leaf = [1, 2, 5, 10] 

hyperF = dict(n_estimators = n_estimators, max_depth = max_depth,  
              min_samples_split = min_samples_split, 
             min_samples_leaf = min_samples_leaf)

gridF = GridSearchCV(model, hyperF, cv = 3, verbose = 1, 
                      n_jobs = -1)
bestF = gridF.fit(X_train, y_train)
print(f'The best hyperparameters are {bestF.best_params_}')
print(f'The accuracy score for the testing dataset is {bestF.score(X_test, y_test):.4f}')
# print(model.score(X_train,y_train))
# print(model.score(X_test,y_test))
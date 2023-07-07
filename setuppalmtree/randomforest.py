import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV, RandomizedSearchCV, cross_val_score,validation_curve
from scipy.stats import randint
from sklearn.ensemble import RandomForestClassifier
#THIS IMPLEMENTATION STILL LACKS ON HYPERPARAMETER TUNING
#THIS HAS TO BE CHANGED LATER ON:
dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
df = pd.concat([dfb,dfm])

y=df.iloc[:,1].values
X=df.iloc[:,2:].values

X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=0)

sc=StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.fit_transform(X_test)

#CLASSIFIERS
#this model has an accuracy of .8697
# model = RandomForestClassifier(n_estimators=1200,max_depth=25,min_samples_leaf=1,min_samples_split=2, criterion='entropy',random_state=0)
#this model is even better accuracy of .8717
# model = RandomForestClassifier(max_depth= 30, min_samples_leaf= 1, min_samples_split=2, n_estimators= 1300, criterion='entropy',random_state=0)
# model.fit(X_train,y_train)
# print(model.score(X_train,y_train))
# print(model.score(X_test,y_test))
model=RandomForestClassifier(criterion='entropy',random_state=0)
#HYPERPARAMETER OPTIMIZATION
#GridSearch
#MAYBE INCREASE THE NUMBER OF ESTIMATORS IN FUTURE TUNING SESSIONS.
# n_estimators=[100, 300, 500, 800, 1200]
n_estimators = [1200, 1300, 1400, 1500,1600,1700]
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
# VALIDATION CURVES:
# num_est=[100, 300, 500, 750, 800, 1200]
# train_scoreNum, test_scoreNum = validation_curve(
#                                 RandomForestClassifier(),
#                                 X = X_train, y = y_train, 
#                                 param_name = 'n_estimators', 
#                                 param_range = num_est, cv = 3)
# forestVC = RandomForestClassifier(random_state = 1,
#                                   n_estimators = 750,
#                                   max_depth = 15, 
#                                   min_samples_split = 5,  min_samples_leaf = 1) 
# modelVC = forestVC.fit(X_train, y_train) 
# y_predVC = modelVC.predict(X_test)
# print(modelVC.score(X_train,y_train))
# print(modelVC.score(X_test,y_test))
#RANDOM SEARCH
# rf = RandomForestClassifier()
# rs_space={'max_depth':list(np.arange(10, 100, step=10)) + [None],
#               'n_estimators':np.arange(10, 500, step=50),
#               'max_features':randint(1,7),
#               'criterion':['gini','entropy'],
#               'min_samples_leaf':randint(1,4),
#               'min_samples_split':np.arange(2, 10, step=2)
#          }
# rf_random = RandomizedSearchCV(rf, rs_space, n_iter=500, scoring='accuracy', n_jobs=-1, cv=3)
# model_random = rf_random.fit(X_train,y_train)
# print('Best hyperparameters are: '+str(model_random.best_params_))
# print('Best score is: '+str(model_random.best_score_))


# print(model.score(X_train,y_train))
# print(model.score(X_test,y_test))
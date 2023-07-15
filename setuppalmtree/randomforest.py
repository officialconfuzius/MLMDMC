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
#this model has an accuracy of .5202 on the testing set tf-idf
# model = RandomForestClassifier(max_depth=30,min_samples_leaf=1,min_samples_split=5,n_estimators=1200)
#this model has an accuracy of .8697
# model = RandomForestClassifier(n_estimators=1200,max_depth=25,min_samples_leaf=1,min_samples_split=2, criterion='entropy',random_state=0)
#this model is even better accuracy of .8717
# model = RandomForestClassifier(max_depth= 30, min_samples_leaf= 1, min_samples_split=2, n_estimators= 1300, criterion='entropy',random_state=0)
# accuracies = cross_val_score(estimator = model, X = X_train, y = y_train, cv = 40)
# print(accuracies.mean())
# print(accuracies.std())
# model.fit(X_train,y_train)

# print(model.score(X_train,y_train))
# print(model.score(X_test,y_test))

# model.fit(X_train,y_train)
# print(model.score(X_train,y_train))
# print(model.score(X_test,y_test))
# model=RandomForestClassifier(criterion='entropy',random_state=0)

model = RandomForestClassifier(random_state=0,criterion='entropy')
# #HYPERPARAMETER OPTIMIZATION
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

#UNCOMMENT THE FOLLOWING LINES FOR RANDOM SEARCH OPTIMIZATION: (accuracy=0.8036)
# List of C values
# C_range = np.logspace(-10, 10, 21)
# print(f'The list of values for C are {C_range}')
# # List of gamma values
# gamma_range = np.logspace(-10, 10, 21)
# print(f'The list of values for gamma are {gamma_range}')

# # Define the search space
# param_grid = { 
#     # Regularization parameter.
#     "C": C_range,
#     # Kernel type
#     "kernel": ['rbf', 'poly'],
#     # Gamma is the Kernel coefficient for ‘rbf’, ‘poly’ and ‘sigmoid’.
#     "gamma": gamma_range.tolist()+['scale', 'auto']
#     }
# # Set up score
# scoring = ['accuracy']
# # Set up the k-fold cross-validation
# kfold = StratifiedKFold(n_splits=3, shuffle=True, random_state=0)
# # Define random search
# random_search = RandomizedSearchCV(estimator=svc, 
#                            param_distributions=param_grid, 
#                            n_iter=100,
#                            scoring=scoring, 
#                            refit='accuracy', 
#                            n_jobs=-1, 
#                            cv=kfold, 
#                            verbose=0)
# # Fit grid search
# random_result = random_search.fit(X_train, y_train)
# # Print grid search summary
# print(random_result)

# # Print the best accuracy score for the training dataset
# print(f'The best accuracy score for the training dataset is {random_result.best_score_:.4f}')
# # Print the hyperparameters for the best score
# print(f'The best hyperparameters are {random_result.best_params_}')
# # Print the best accuracy score for the testing dataset
# print(f'The accuracy score for the testing dataset is {random_search.score(X_test, y_test):.4f}')
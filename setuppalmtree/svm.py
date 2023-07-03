import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV, RandomizedSearchCV, cross_val_score
from hyperopt import tpe, STATUS_OK, Trials, hp, fmin, space_eval
from sklearn.svm import SVC

dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
df = pd.concat([dfb,dfm])

y=df.iloc[:,1].values
X=df.iloc[:,2:].values

X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=0)

sc=StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.fit_transform(X_test)

svc=SVC()

#HYPERPARAMETER TUNING, ALL ACCURACIES ARE GENERATED FROM A DATASET WITH 277 ENTRIES (162 malicious, 115 benign)
#FOR GRIDSEARCH UNCOMMENT THE FOLLOWING LINES (accuracy=0.8036)
# # List of C values
# C_range = np.logspace(-1, 1, 3)
# print(f'The list of values for C are {C_range}')
# # List of gamma values
# gamma_range = np.logspace(-1, 1, 3)
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

# # Define grid search
# grid_search = GridSearchCV(estimator=svc, 
#                            param_grid=param_grid, 
#                            scoring=scoring, 
#                            refit='accuracy', 
#                            n_jobs=-1, 
#                            cv=kfold, 
#                            verbose=0)
# # Fit grid search
# grid_result = grid_search.fit(X_train, y_train)
# # Print grid search summary
# print(grid_result)
# # Print the best accuracy score for the training dataset
# print(f'The best accuracy score for the training dataset is {grid_result.best_score_:.4f}')
# # Print the hyperparameters for the best score
# print(f'The best hyperparameters are {grid_result.best_params_}')
# # Print the best accuracy score for the testing dataset
# print(f'The accuracy score for the testing dataset is {grid_search.score(X_test, y_test):.4f}')

# svm = SVC(kernel='linear',random_state=0,C=2.0,gamma=12)
# # svm = SVC(kernel='rbf',random_state=0)
# accuracies = cross_val_score(estimator = svm, X = X_train, y = y_train, cv = 40)
# print(accuracies.mean())
# print(accuracies.std())
# # svm.fit(X_train,y_train)

# # print(svm.score(X_train,y_train))
# # print(svm.score(X_test,y_test))

#UNCOMMENT THE FOLLOWING LINES FOR RANDOM SEARCH OPTIMIZATION: (accuracy=0.8036)
# # List of C values
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

#UNCOMMENT THE FOLLOWING LINES FOR BAYESIAN OPTIMIZATION: (accuracy=0.7857)
# Space
# gamma_range = np.logspace(-10, 10, 21)
# C_range = np.logspace(-10, 10, 21)
# space = {
#     'C' : hp.choice('C', C_range),
#     'gamma' : hp.choice('gamma', gamma_range.tolist()+['scale', 'auto']),
#     'kernel' : hp.choice('kernel', ['rbf', 'poly'])
# }
# # Set up the k-fold cross-validation
# kfold = StratifiedKFold(n_splits=3, shuffle=True, random_state=0)
# # Objective function
# def objective(params):
    
#     svc = SVC(**params)
#     scores = cross_val_score(svc, X_train, y_train, cv=kfold, scoring='accuracy', n_jobs=-1)
#     # Extract the best score
#     best_score = np.mean(scores)
#     # Loss must be minimized
#     loss = - best_score
#     # Dictionary with information for evaluation
#     return {'loss': loss, 'params': params, 'status': STATUS_OK}
# # Trials to track progress
# bayes_trials = Trials()
# # Optimize
# best = fmin(fn = objective, space = space, algo = tpe.suggest, max_evals = 100, trials = bayes_trials)

# # Print the index of the best parameters
# print(best)
# # Print the values of the best parameters
# print(space_eval(space, best))

# # Train model using the best parameters
# svc_bo = SVC(C=space_eval(space, best)['C'], gamma=space_eval(space, best)['gamma'], kernel=space_eval(space, best)['kernel']).fit(X_train,y_train)
# # Print the best accuracy score for the testing dataset
# print(f'The accuracy score for the testing dataset is {svc_bo.score(X_test, y_test):.4f}')

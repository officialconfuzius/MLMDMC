import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn import metrics
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

#this new configuration has an accuracy of .6191 on the testing set tf-idf
svc=SVC(C=10.0,gamma=10.0,kernel='poly')
#this configuration has an accuracy of .8837
# svc=SVC(gamma=0.1,C=10.0,kernel='rbf')
#this configuration has an accuracy of .8739
# svc=SVC(gamma=0.1,C=1.0,kernel="rbf")
# svc=SVC()

# accuracies = cross_val_score(estimator = svc, X = X_train, y = y_train, cv = 40)
# print(accuracies.mean())
# print(accuracies.std())
svc.fit(X_train,y_train)

# print(svc.score(X_train,y_train))
# print(svc.score(X_test,y_test))


confusion_matrix = metrics.confusion_matrix(y_test, svc.predict(X_test))
cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix = confusion_matrix, display_labels = [False, True])

cm_display.plot()
plt.show()

#HYPERPARAMETER TUNING, ALL ACCURACIES ARE GENERATED FROM A DATASET WITH 277 ENTRIES (162 malicious, 115 benign)
# FOR GRIDSEARCH UNCOMMENT THE FOLLOWING LINES (accuracy=0.8036)
# List of C values
# C_range = np.logspace(-1, 1, 3)
# C_range = [10,15,20,25]
# print(f'The list of values for C are {C_range}')
# # List of gamma values
# # gamma_range = np.logspace(-1, 1, 3)
# gamma_range = [10,15,20,25]
# print(f'The list of values for gamma are {gamma_range}')

# # Define the search space
# param_grid = { 
#     # Regularization parameter.
#     "C": C_range,
#     # Kernel type
#     "kernel": ['rbf', 'poly','linear'],
#     # Gamma is the Kernel coefficient for ‘rbf’, ‘poly’ and ‘sigmoid’.
#     # "gamma": gamma_range.tolist()+['scale', 'auto']
#     "gamma":gamma_range+["scale","auto"]
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

# # svm = SVC(kernel='linear',random_state=0,C=2.0,gamma=12)
# svm = SVC(kernel='rbf',random_state=0)

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
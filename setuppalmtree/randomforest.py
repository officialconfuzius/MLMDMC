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
df = pd.read_csv("out/oversamplingstfidf.csv")

# dfm = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
# dfb = pd.read_csv("out/Benigns/out/benignembeddings.csv",header=None)
# df = pd.concat([dfb,dfm])

#for oversampled data: 
y = df.iloc[:,0].values
X= df.iloc[:,1:].values
# y=df.iloc[:,1].values
# X=df.iloc[:,2:].values

X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.2,random_state=0)

sc=StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.fit_transform(X_test)

#CLASSIFIERS
#this model has an accuracy of .9111 on testing set of extended arithemetic mean: 
# model = RandomForestClassifier(max_depth=30,min_samples_leaf=1,min_samples_split=2,n_estimators=800)
#this model has an accuracy of .5202 on the testing set tf-idf
# model = RandomForestClassifier(max_depth=30,min_samples_leaf=1,min_samples_split=5,n_estimators=1200)
#this model has an accuracy of .8697
# model = RandomForestClassifier(n_estimators=1200,max_depth=25,min_samples_leaf=1,min_samples_split=2, criterion='entropy',random_state=0)
#this model is even better accuracy of .8717 embeddings mean choice
# model = RandomForestClassifier(max_depth= 30, min_samples_leaf= 1, min_samples_split=2, n_estimators= 1300, criterion='entropy',random_state=0)
# configuration for tf-idf extended accuracy of .6735
model = RandomForestClassifier(max_depth=30,min_samples_leaf=1,min_samples_split=2,n_estimators=500)
model.fit(X_train,y_train)
#Confusion matrix:
confusion_matrix = confusion_matrix(y_test, model.predict(X_test))
cm_display = ConfusionMatrixDisplay(confusion_matrix = confusion_matrix, display_labels = [False, True])

cm_display.plot()
plt.savefig("out/rftf-idfext")

predictions=model.predict(X_test)
# calculate the accuracy score: 
accuracyScore=accuracy_score(y_test,predictions)
tn, fp, fn, tp = confusion_matrix.ravel()
specificity = tn / (tn+fp)
sensitivity = tp / (tp+fn)
gscore = sqrt(sensitivity*specificity)
print("accuracy:"+str(accuracyScore))
print("specificity:"+str(specificity))
print("sensitivity:"+str(sensitivity))
print("GScore:"+str(gscore))

#get f1, recall and precision scores: 
precision=precision_score(y_test,predictions)
recall = recall_score(y_test,predictions)
f1score = f1_score(y_test,predictions)
print("precision:"+str(precision))
print("recall:"+str(recall))
print("f1 score:"+str(f1score))

# model.fit(X_train,y_train)
# print(model.score(X_train,y_train))
# print(model.score(X_test,y_test))


# model = RandomForestClassifier(random_state=0,criterion='entropy')
# # # #HYPERPARAMETER OPTIMIZATION
# # #GridSearch
# n_estimators=[100, 300, 500, 800, 1200]
# n_estimators = [1200, 1300, 1400, 1500,1600,1700]
# max_depth = [5, 8, 15, 25, 30]
# min_samples_split = [2, 5, 10, 15, 100]
# min_samples_leaf = [1, 2, 5, 10] 

# hyperF = dict(n_estimators = n_estimators, max_depth = max_depth,  
#               min_samples_split = min_samples_split, 
#              min_samples_leaf = min_samples_leaf)
# kfold = StratifiedKFold(n_splits=3, shuffle=True, random_state=0)
# gridF = GridSearchCV(model, hyperF, cv = kfold, verbose = 1, 
#                       n_jobs = -1)
# bestF = gridF.fit(X_train, y_train)
# print(f'The best hyperparameters are {bestF.best_params_}')
# print(f'The accuracy score for the testing dataset is {bestF.score(X_test, y_test):.4f}')

#UNCOMMENT THE FOLLOWING LINES FOR RANDOM SEARCH OPTIMIZATION:
#define search space
# n_estimators=[100, 300, 500, 800, 1200,1300,1400,1500,1600,1700,1800,1900]
# max_depth= [5, 8, 15, 25, 30,40,50,60,70]
# min_samples_leaf = [1, 2, 5, 10,20,40,80] 
# min_samples_split = [2, 5, 10, 15, 50, 100, 200]

# # # Define the search space
# param_grid = { 
#     "n_estimators": n_estimators,
#     # Kernel type
#     "max_depth": max_depth,
#     # Gamma is the Kernel coefficient for ‘rbf’, ‘poly’ and ‘sigmoid’.
#     "min_samples_leaf": min_samples_leaf,
#     "min_samples_split": min_samples_split
#     }
# Set up score
# scoring = ['accuracy']
# # Set up the k-fold cross-validation
# kfold = StratifiedKFold(n_splits=3, shuffle=True, random_state=0)
# # Define random search
# random_search = RandomizedSearchCV(estimator=model, 
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
from sklearn.cluster import KMeans
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt

#import the malware features
df = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
#select the embeddings
X=df.iloc[:,2:].values
#standardize the data
sc=StandardScaler()
X = sc.fit_transform(X)
#setup kmeans
kmeans = KMeans(n_clusters=4)
kmeans.fit(X)
#append the labels of kmeans to the dataframe
df["cluster"]=kmeans.labels_
#load in the gold standard
infectedputty = np.load("../Goldstandard/out/infectputty.exe.textAM.npy")
goldarray = [infectedputty]
#make a prediction for the gold standard
goldpred = kmeans.predict(goldarray)
#print the output:
print("infected putty prediction: "+str(goldpred[0]))
#select the type of malware
firstcol = df.iloc[:,0:1]
firstcol = firstcol.to_numpy()
#select the predicted label
lastcol = df["cluster"].to_numpy()
#initialize a dictonary, which contains all the clusters.
dict = {}
for t in lastcol: 
    if t not in dict.keys(): 
        dict[t] = {}
#fill the dictonary, with dictionaries that contain all malware types inside the cluster.
for iterator in range(0,len(firstcol)):
    if firstcol[iterator] == 1: 
        #find key
        key = lastcol[iterator]
        if "Virus" not in dict[key].keys(): 
            dict[key]["Virus"] = 1
        else: 
            dict[key]["Virus"] = dict[key]["Virus"] + 1
    elif firstcol[iterator] == 2: 
        #find key
        key = lastcol[iterator]
        if "Backdoor" not in dict[key].keys(): 
            dict[key]["Backdoor"] = 1
        else: 
            dict[key]["Backdoor"] = dict[key]["Backdoor"] + 1
    elif firstcol[iterator] == 3: 
        #find key
        key = lastcol[iterator]
        if "Worm" not in dict[key].keys(): 
            dict[key]["Worm"] = 1
        else: 
            dict[key]["Worm"] = dict[key]["Worm"] + 1
    elif firstcol[iterator] == 4: 
        #find key
        key = lastcol[iterator]
        if "Trojan" not in dict[key].keys(): 
            dict[key]["Trojan"] = 1
        else: 
            dict[key]["Trojan"] = dict[key]["Trojan"] + 1
    elif firstcol[iterator] == 5: 
        #find key
        key = lastcol[iterator]
        if "Exploit" not in dict[key].keys(): 
            dict[key]["Exploit"] = 1
        else: 
            dict[key]["Exploit"] = dict[key]["Exploit"] + 1
    elif firstcol[iterator] == 6: 
        #find key
        key = lastcol[iterator]
        if "Hoax" not in dict[key].keys(): 
            dict[key]["Hoax"] = 1
        else: 
            dict[key]["Hoax"] = dict[key]["Hoax"] + 1
    elif firstcol[iterator] == 7: 
        #find key
        key = lastcol[iterator]
        if "Dos" not in dict[key].keys(): 
            dict[key]["Dos"] = 1
        else: 
            dict[key]["Dos"] = dict[key]["Dos"] + 1
    elif firstcol[iterator] == 8: 
        #find key
        key = lastcol[iterator]
        if "Flooder" not in dict[key].keys(): 
            dict[key]["Flooder"] = 1
        else: 
            dict[key]["Flooder"] = dict[key]["Flooder"] + 1
    elif firstcol[iterator] == 9: 
        #find key
        key = lastcol[iterator]
        if "Rootkit" not in dict[key].keys(): 
            dict[key]["Rootkit"] = 1
        else: 
            dict[key]["Rootkit"] = dict[key]["Rootkit"] + 1
    elif firstcol[iterator] == 10: 
        #find key
        key = lastcol[iterator]
        if "Spamtool" not in dict[key].keys(): 
            dict[key]["Spamtool"] = 1
        else: 
            dict[key]["Spamtool"] = dict[key]["Spamtool"] + 1
    elif firstcol[iterator] == 11: 
        #find key
        key = lastcol[iterator]
        if "Spoofer" not in dict[key].keys(): 
            dict[key]["Spoofer"] = 1
        else: 
            dict[key]["Spoofer"] = dict[key]["Spoofer"] + 1
    elif firstcol[iterator] == 12: 
        #find key
        key = lastcol[iterator]
        if "Packed" not in dict[key].keys(): 
            dict[key]["Packed"] = 1
        else: 
            dict[key]["Packed"] = dict[key]["Packed"] + 1
    elif firstcol[iterator] == 13: 
        #find key
        key = lastcol[iterator]
        if "No_Match" not in dict[key].keys(): 
            dict[key]["No_Match"] = 1
        else: 
            dict[key]["No_Match"] = dict[key]["No_Match"] + 1
sumofall = 0
maxValues = []
#select top 3 malware types per cluster: 
for entry in dict.keys(): 
    #iteration for every cluster: 
    print("Cluster number: " + str(entry))
    maxValue = 0
    secondBestValue = 0
    thirdBestValue = 0
    maxKey = ""
    secondMaxKey = ""
    thirdMaxKey = ""
    stringkeys = ""
    sumofallinsidecluster = 0
    for k in dict[entry].keys():
        stringkeys = stringkeys + k + " "
    print("All represented malware types: " + stringkeys)
    for key in dict[entry].keys():
        #sum everything up
        #for every single data point
        sumofall += dict[entry][key]
        #for every single data point in the cluster
        sumofallinsidecluster += dict[entry][key]
        #iteration for every malware type inside the cluster
        if dict[entry][key] > maxValue: 
            thirdMaxKey = secondMaxKey
            thirdBestValue = secondBestValue
            secondMaxKey = maxKey
            maxKey = key
            secondBestValue = maxValue
            maxValue = dict[entry][key]
        elif dict[entry][key] > secondBestValue: 
            thirdMaxKey = secondMaxKey
            secondMaxKey = key
            thirdBestValue = secondBestValue
            secondBestValue = dict[entry][key]
        elif dict[entry][key] > thirdBestValue:
            thirdMaxKey = key
            thirdBestValue = dict[entry][key]
    maxValues.append(maxValue)
    purity = maxValue / sumofallinsidecluster
    print("purity of this cluster: "+ str(purity))
    print(maxKey + ": " + str(maxValue))
    print(secondMaxKey + ": " + str(secondBestValue))
    print(thirdMaxKey + ": " + str(thirdBestValue))
sumofallmaxes = 0
for mv in maxValues: 
    sumofallmaxes += mv
purityofall = sumofallmaxes / sumofall
print("purity of the whole clustering: "+str(purityofall))
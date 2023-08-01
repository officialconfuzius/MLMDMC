from sklearn.cluster import KMeans
import pandas as pd
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
#read the malicious features
df = pd.read_csv("out/Malicious/out/maliciousembeddingstfidf.csv",header=None)
#create an array for the cluster configurations
means = []
#create an array for the inertia scores of the cluster configurations
inertias = []
#select the embeddings
X=df.iloc[:,2:].values
#standardize the data
sc=StandardScaler()
X = sc.fit_transform(X)
#gather the data for the curve
for i in range(1,16):
    kmeans = KMeans(n_clusters=i,random_state=0)
    kmeans.fit(X)
    means.append(i)
    inertias.append(kmeans.inertia_)
#plot the curve
fig = plt.subplots(figsize=(10,5))
plt.plot(means,inertias,"o-")
plt.grid(True)
plt.xlabel("clusters")
plt.ylabel("inertias")
plt.show()
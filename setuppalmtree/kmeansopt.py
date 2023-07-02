from sklearn.cluster import KMeans
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
means = []
inertias = []
for i in range(1,11):
    kmeans = KMeans(n_clusters=i,random_state=0)
    kmeans.fit(df.iloc[:,1:])
    means.append(i)
    inertias.append(kmeans.inertia_)

fig = plt.subplots(figsize=(10,5))
plt.plot(means,inertias,"o-")
plt.grid(True)
plt.xlabel("clusters")
plt.ylabel("inertias")
plt.show()
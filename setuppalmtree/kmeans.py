from sklearn.cluster import KMeans
import pandas as pd
import matplotlib.pyplot as plt


df = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
print(df)
#setup kmeans
kmeans = KMeans(n_clusters=3)
kmeans.fit(df.iloc[:,1:])
df["cluster"]=kmeans.labels_
print(df)

#maybe plot the results. tbd
#plt.scatter(x=?,y=?,c=df["cluster"])



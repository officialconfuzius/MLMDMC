from sklearn.cluster import KMeans
import pandas as pd
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt


df = pd.read_csv("out/Malicious/out/maliciousembeddings.csv",header=None)
X=df.iloc[:,2:].values
sc=StandardScaler()
X = sc.fit_transform(X)
#setup kmeans
kmeans = KMeans(n_clusters=6)
kmeans.fit(X)
df["cluster"]=kmeans.labels_
print(df)

#plot the results. tbd
#plt.scatter(x=?,y=?,c=df["cluster"])



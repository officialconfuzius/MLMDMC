import pandas as pd

df = pd.read_csv("out/idfscores.csv")


print(df.nsmallest(100,"document_frequency"))

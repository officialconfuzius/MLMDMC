with open("../setuppalmtree/out/Malicious/out/maliciousembeddings.csv","r") as inp: 
    with open("../setuppalmtree/out/Malicious/out/maliciousembeddingsnew.csv","a") as out: 
        i = 0
        ar = inp.readlines()
        while i < len(ar): 
            if i <= 2950: 
                out.write(ar[i])
            else: 
                string = ar[i]
                append = string[1:]
                out.write("4"+append)
            i+=1
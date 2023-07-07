ar = ["test","me","now","me","now","me","now","me","now"]
scores = [1, 0, 1, 0, 1, 0, 1, 0, 1]

def minimizearray(array,tfidfar):
    i = 0
    while (i < len(array)): 
        if(tfidfar[i]==0.0): 
            array.pop(i)
            tfidfar.pop(i)
            continue
        else:
            i+=1
    return array

print(scores)
print(ar)
ar=minimizearray(ar,scores)
print(scores)
print(ar)

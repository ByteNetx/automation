from cryptography.fernet import Fernet
from pathlib import Path

basePath = Path.home() / 'pyenv3.9' / 'cisco'
credFile = f"{basePath}/data/myCredetials.bin"

# Generate a key that will be used to encrypt the credentials
myKey = Fernet.generate_key()
f = Fernet(myKey)

credentials = input("Enter admin password and enable secret separated by a single whitespace\n")

cred_bytes = credentials.encode('utf-8')
encrypted_credentials = f.encrypt(cred_bytes)
with open(credFile, 'wb') as f:
    f.write(encrypted_credentials)

print("Add the below encrypt key to the CyberArk, which is required\n to run admin rotation script!!!\n")
print("="*len("Add the below encrypt key to the CyberArk, which is required"))
print(myKey.decode('utf-8'))
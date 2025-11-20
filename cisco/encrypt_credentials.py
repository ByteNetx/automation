#!"C:\Users\tyu1\pyenv3.9\Scripts\python.exe"
from cryptography.fernet import Fernet
from colorama import Fore, Back, Style, init
from pathlib import Path
import argparse, os, sys

init(autoreset=True) # Automatically resets style after each print

def banner(action):
    if action == 'encrypt':
        print(Fore.YELLOW+r"""
******************************************************************************
*  _____                             _     ____                     _        *
* | ____|_ __   ___ _ __ _   _ _ __ | |_  / ___|  ___  ___ _ __ ___| |_ ___  *
* |  _| | '_ \ / __| '__| | | | '_ \| __| \___ \ / _ \/ __| '__/ _ \ __/ __| *
* | |___| | | | (__| |  | |_| | |_) | |_   ___) |  __/ (__| | |  __/ |_\__ \ *
* |_____|_| |_|\___|_|   \__, | .__/ \__| |____/ \___|\___|_|  \___|\__|___/ *
*                        |___/|_|                                            *
******************************************************************************
""")
    elif action == 'decrypt':
        print(Fore.YELLOW+r"""
*****************************************************************************
*  ____                             _     ____                     _        *
* |  _ \  ___  ___ _ __ _   _ _ __ | |_  / ___|  ___  ___ _ __ ___| |_ ___  *
* | | | |/ _ \/ __| '__| | | | '_ \| __| \___ \ / _ \/ __| '__/ _ \ __/ __| *
* | |_| |  __/ (__| |  | |_| | |_) | |_   ___) |  __/ (__| | |  __/ |_\__ \ *
* |____/ \___|\___|_|   \__, | .__/ \__| |____/ \___|\___|_|  \___|\__|___/ *
*                       |___/|_|                                            *
*****************************************************************************
""")
def encrypt(credFile):
    # Generate an encryption key that will be used to encrypt the credentials
    myKey = Fernet.generate_key()
    f = Fernet(myKey)
    
    secret = input(Fore.GREEN+"Enter your secret to encrypt:"+Fore.RESET)

    credential = secret.strip().encode('utf-8')
    encrypted_credential = f.encrypt(credential)

    if os.path.exists(credFile):
        confirm = input("The encrypted secret file exists! Please enter Yes to continue or No to quit:")
        if confirm == 'Yes' or confirm == 'yes':
            with open(credFile, 'wb') as f:
                f.write(encrypted_credential)
            
            print(Fore.GREEN+"\nAdd the below encryption key to the CyberArk, which is required\n to run admin rotation script!!!")
            print("="*len("Add the below encryption key to the CyberArk, which is required "))
            print(Fore.BLUE+myKey.decode('utf-8'))
        else:
            sys.exit()

def decrypt(credFile):
    # Get the decryption key from standard input
    try:
        with open(credFile, 'rb') as f:
            encrypted_credential = f.read()
    except (FileNotFoundError,PermissionError,NameError) as e:
        print(e)
    else:
        myKey = input(Fore.GREEN+"Enter your decryption key:"+Fore.RESET)
        f = Fernet(myKey.strip())
        decrypted_credential = f.decrypt(encrypted_credential)
        secret = decrypted_credential.decode('utf-8')
        print(f"Your secret:{Fore.BLUE}{secret}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--action', choices=['encrypt', 'decrypt'], default = 'decrypt'
    )
    args = parser.parse_args()

    basePath = Path.home() / 'pyenv3.9' / 'secret'
    credFile = f"{basePath}/myCredetial.bin"

    banner(args.action)
    if args.action == 'encrypt': 
        encrypt(credFile)
    elif args.action == 'decrypt':
        decrypt(credFile)

if __name__ == "__main__":
    main()

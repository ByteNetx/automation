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
    
    passwd = input(Fore.GREEN+"Enter the admin password to encrypt:"+Fore.RESET)
    secret = input(Fore.GREEN+"Enter the enable secret to encrypt:"+Fore.RESET)

    credential = (f"{passwd.strip()} {secret.strip()}").encode('utf-8')
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
    else:
        with open(credFile, 'wb') as f:
            f.write(encrypted_credential)
        
        print(Fore.GREEN+"\nAdd the below encryption key to the CyberArk, which is required\n to run admin rotation script!!!")
        print("="*len("Add the below encryption key to the CyberArk, which is required "))
        print(Fore.BLUE+myKey.decode('utf-8'))

def decrypt(credFile):
    # Get the decryption key from standard input
    try:
        with open(credFile, 'rb') as f:
            encrypted_credential = f.read()
    except (FileNotFoundError,PermissionError,NameError) as e:
        print(e)
        sys.exit()
    else:
        myKey = input(Fore.GREEN+"Enter your decryption key:"+Fore.RESET)
        f = Fernet(myKey.strip())
        decrypted_credential = f.decrypt(encrypted_credential)
        credential = decrypted_credential.decode('utf-8')
        return credential

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--action', help="Enter the action from choices of encrypt and decrypt. Default to action decrypt.", choices=['encrypt', 'decrypt'], default = 'decrypt'
    )
    parser.add_argument(
        '--f', help="The encrypted credential file", type=str, required=True
    )
    args = parser.parse_args()

    basePath = Path.home() / 'pyenv3.9' / 'secrets'
    credFile = f"{basePath}/{args.f}"

    banner(args.action)
    if args.action == 'encrypt': 
        encrypt(credFile)
    elif args.action == 'decrypt':
        credentials = decrypt(credFile)
        passwd = credentials.split()[0]
        secret = credentials.split()[1]
        print(f"The admin password:{Fore.BLUE}{passwd}{Fore.RESET}\nThe enable secret:{Fore.BLUE}{secret}")

if __name__ == "__main__":
    main()


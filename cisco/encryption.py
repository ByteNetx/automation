from cryptography.fernet import Fernet
from colorama import Fore, Back, Style, init
from pathlib import Path
import argparse, os, sys, json

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
def encrypt(credFile, action):
    # Generate an encryption key that will be used to encrypt the credentials
    myKey = Fernet.generate_key()
    f = Fernet(myKey)
    
    if os.path.exists(credFile):
        credentials = decrypt(credFile)
    else:
        credentials = {}
    
    if action == 'add':
        while True:
            choice = input("Enter 'yes' to add an account or 'no' to quit: ").lower()
            if choice == 'yes':
                username = input("Enter Username: ")
                password = input("Enter Password: ")
                credentials.update({username: password})
            elif choice == 'no':
                break  # Valid input, exit loop
        new_credentials = {k: v for k,v in credentials.items()}
    elif action == 'delete':
        del_account = input("Enter the account to be removed: ")
        new_credentials = {k: v for k,v in credentials.items() if k != del_account}

 
    cred_byptes = json.dumps(new_credentials).encode('utf-8')
    encrypted_credential = f.encrypt(cred_byptes)

    with open(credFile, 'wb') as f:
        f.write(encrypted_credential)
    print(f"\n{Fore.GREEN}Updated credentials in {credFile}{Fore.RESET}\n")
    print("The below key is required to decrypt stored credentials: ")
    print("="*len("The below key is required to decrypt stored credentials: "))
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
        credentials = json.loads(decrypted_credential.decode('utf-8'))
        return credentials

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--action', help="Enter the action from choices. Default to action show.", choices=['show', 'add', 'delete'], default = 'show'
    )
    parser.add_argument(
        '--f', help="The encrypted credential file", type=str, required=True
    )
    args = parser.parse_args()

    basePath = Path.home() / 'pyenv3.9' / 'secrets'
    credFile = f"{basePath}/{args.f}"

    banner(args.action)
    if args.action != 'show':
        encrypt(credFile, args.action)
    elif args.action == 'show':
        credentials = decrypt(credFile)
        print("\n------------Credentials List------------")
        for u, p in credentials.items():
            print(f"{Fore.CYAN}{u}: {p}{Fore.RESET}")

if __name__ == "__main__":
    main()

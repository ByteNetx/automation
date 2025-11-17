from cryptography.fernet import Fernet
from colorama import Fore, Back, Style, init
from pathlib import Path

init(autoreset=True) # Automatically resets style after each print

def banner():
    print(Fore.YELLOW+r"""
**********************************************************************************
*                                                                                *
*   ______                             _      _____                    _         *
*  |  ____|                           | |    / ____|                  | |        *
*  | |__   _ __   ___ _ __ _   _ _ __ | |_  | (___   ___  ___ _ __ ___| |_ ___   *
*  |  __| | '_ \ / __| '__| | | | '_ \| __|  \___ \ / _ \/ __| '__/ _ \ __/ __|  *
*  | |____| | | | (__| |  | |_| | |_) | |_   ____) |  __/ (__| | |  __/ |_\__ \  *
*  |______|_| |_|\___|_|   \__, | .__/ \__| |_____/ \___|\___|_|  \___|\__|___/  *
*                           __/ | |                                              *
*                          |___/|_|                                              *
*                                                                                *
*  By: Tao                                                       Version: 0.1    *
**********************************************************************************
""")
def app_run():
    basePath = Path.home() / 'netdev' / 'python-env' / 'cisco'
    credFile = f"{basePath}/data/myCredetials.bin"
    
    # Generate a key that will be used to encrypt the credentials
    myKey = Fernet.generate_key()
    f = Fernet(myKey)
    
    admin_passwd = input(Fore.GREEN+"Enter admin password in plain text:"+Fore.RESET)
    enable_secret = input(Fore.GREEN+"Enter enable secret in plain text:"+Fore.RESET)

    credentials = f"{admin_passwd.strip()} {enable_secret.strip()}"
    cred_bytes = credentials.encode('utf-8')
    encrypted_credentials = f.encrypt(cred_bytes)
    with open(credFile, 'wb') as f:
        f.write(encrypted_credentials)
    
    print(Fore.GREEN+"\nAdd the below encryption key to the CyberArk, which is required\n to run admin rotation script!!!")
    print("="*len("Add the below encryption key to the CyberArk, which is required "))
    print(Fore.BLUE+myKey.decode('utf-8'))

def main():
    banner()
    app_run()

if __name__ == "__main__":
    main()


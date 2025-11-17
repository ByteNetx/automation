import random, base64
import sys, hashlib
from colorama import Fore, Back, Style, init

init(autoreset=True)

# Translate Standard Base64 table to Cisco Base64 Table used in Type8 and TYpe 9                                                
std_b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
cisco_b64chars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
b64table = str.maketrans(std_b64chars, cisco_b64chars)

class InvalidPassword(Exception):
    """
    Exception to be thrown if an invalid password is submitted to be hashed.
    """
    pass

def banner():
    print("""
*********************************************************************************
*   ____ _                 _____                  ___    _   _           _      *
*  / ___(_)___  ___ ___   |_   _|   _ _ __   ___ / _ \  | | | | __ _ ___| |__   *
* | |   | / __|/ __/ _ \    | || | | | '_ \ / _ \ (_) | | |_| |/ _` / __| '_ \  *
* | |___| \__ \ (_| (_) |   | || |_| | |_) |  __/\__, | |  _  | (_| \__ \ | | | *
*  \____|_|___/\___\___/    |_| \__, | .__/ \___|  /_/  |_| |_|\__,_|___/_| |_| *
*                               |___/|_|                                        *
*********************************************************************************
""")

def pwd_check(pwd):
    invalid_chars = r"?\""
    if any(char in invalid_chars for char in pwd):
        raise InvalidPassword(r'? and \" are invalid characters for Cisco passwords.')

def hash_type9():
    banner()
    while True:
        pwd = input(Fore.GREEN+"Enter a plain text password:"+Fore.RESET)
        try:
            pwd_check(pwd)
        except InvalidPassword as exception_string:
            print(exception_string)
            pass
        except KeyboardInterrupt:
            sys.exit()
        else:
            salt_chars = []
            for _ in range(14):
                salt_chars.append(random.choice(cisco_b64chars))
            salt = "".join(salt_chars)
            # Create the hash
            hash = hashlib.scrypt(pwd.encode(), salt=salt.encode(), n=16384, r=1, p=1, dklen=32)
            # Convert the hash from Standard Base64 to Cisco Base64
            hash = base64.b64encode(hash).decode().translate(b64table)[:-1]
            # Print the hash in the Cisco IOS CLI format
            pwd_type9 = f'$9${salt}${hash}'
            return pwd_type9
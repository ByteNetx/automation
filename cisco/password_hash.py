import random, base64, re
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
    print(f"""
################################################################
# Cisco Secret Type 8&9 Password Hasher. The password must be  #
#  - At least 16 characters long                                #
#  - Contains at least one uppercase letter                    #
#  - Contains at least one lowercase letter                    #
#  - Contains at least one digit                               #
#  - Contains at least one special character                   #
#  - Does not contain three consecutive identical characters   #
################################################################
""")

def validate_password(pwd):
    invalid_chars = r"(?=.+?[/?:,.\'\\])"
    password_pattern = r"^(?!.*(\w)\1{2,})(?!.*(\s))(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*()_+=\[\]\{\};\"<>|]).{16,20}$"
    if not re.match(password_pattern, pwd):
        raise InvalidPassword(r"""
Password does not meet the policy policy:
 - Password must be at least 16 characters long
 - Password must contain at least one lowercase letter
 - Password must contain at least one uppercase letter
 - Password must contain at least one digit
 - Password must contain at least one of the following special characters
     !@#$%^&*()_+\[\]\{\};\"<>|
""")

def hash_type8(pwd):
    salt_chars = []
    for _ in range(14):
        salt_chars.append(random.choice(cisco_b64chars))
    salt = "".join(salt_chars)
    # Create the hash
    hash = hashlib.pbkdf2_hmac('sha256', pwd.encode('utf-8'), salt.encode(), 20000, 32)
    # Convert the hash from Standard Base64 to Cisco Base64
    hash = base64.b64encode(hash).decode().translate(b64table)[:-1]
    # Print the hash in the Cisco IOS CLI format
    pwd_type8 = f'$8${salt}${hash}'
    return pwd_type8

def hash_type9(pwd):
    salt_chars = []
    for _ in range(14):
        salt_chars.append(random.choice(cisco_b64chars))
    salt = "".join(salt_chars)
    # Create the hash
    hash = hashlib.scrypt(pwd.encode('utf-8'), salt=salt.encode(), n=16384, r=1, p=1, dklen=32)
    # Convert the hash from Standard Base64 to Cisco Base64
    hash = base64.b64encode(hash).decode().translate(b64table)[:-1]
    # Print the hash in the Cisco IOS CLI format
    pwd_type9 = f'$9${salt}${hash}'
    return pwd_type9

def main():
    banner()
    while True:
        pwd = input(Fore.GREEN+"Enter a plain text password:"+Fore.RESET)
        try:
            validate_password(pwd)
        except InvalidPassword as exception_string:
            print(exception_string)
            pass
        except KeyboardInterrupt:
            sys.exit()
        else:
            if len(sys.argv) > 1:
                if sys.argv[1] == '8':
                    secret  = hash_type8(pwd)
                    print(f"Cisco type8 secret:{Fore.BLUE}{secret}")
                elif sys.argv[1] == '9':
                    secret = hash_type9(pwd)
                    print(f"Cisco type9 secret:{Fore.BLUE}{secret}")
                validate = input("Enter \"yes\" to continue or \"no\" to quit:")
                if validate != "y" and validate != "yes":
                    sys.exit()
            else:
                secret = hash_type9(pwd)
                print(f"Cisco type9 secret:{Fore.BLUE}{secret}")
                validate = input("Enter \"yes\" to continue or \"no\" to quit:")
                if validate != "y" and validate != "yes":
                    sys.exit()

if __name__ == "__main__":
    main()

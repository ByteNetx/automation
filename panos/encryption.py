from cryptography.fernet import Fernet, InvalidToken
from colorama import Fore, Back, Style, init
from pathlib import Path
import argparse
import os
import sys
import json
import base64

init(autoreset=True)  # Automatically resets style after each print

class CredentialManager:
    """A class to manage encrypted credentials storage"""
    
    def __init__(self, filename: str, base_path: Path = None):
        """
        Initialize the CredentialManager
        
        Args:
            filename: Name of the credential file
            base_path: Base directory for storing credentials (default: ~/pyenv3.9/secrets)
        """
        if base_path is None:
            base_path = Path.home() / 'pyenv3.13' / 'secrets'
        
        self.base_path = base_path
        self.filename = filename
        self.cred_file = self.base_path / filename
        self.fernet = None
        self.key = None
        
        # Create directory if it doesn't exist
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def _generate_key(self) -> bytes:
        """Generate a new Fernet encryption key"""
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        return self.key
    
    def _load_key(self, key_str: str) -> bool:
        """
        Load an existing encryption key
        
        Args:
            key_str: The encryption key as a string
            
        Returns:
            bool: True if key is valid, False otherwise
        """
        try:
            # Ensure key is properly encoded
            key_bytes = key_str.strip().encode('utf-8')
            # Validate key format
            self.fernet = Fernet(key_bytes)
            self.key = key_bytes
            return True
        except (ValueError, TypeError, base64.binascii.Error):
            print(Fore.RED + "Invalid encryption key format!" + Fore.RESET)
            return False
    
    def _load_credentials(self) -> dict:
        """
        Load and decrypt credentials from file
        
        Returns:
            dict: Decrypted credentials dictionary
        """
        if not self.cred_file.exists():
            return {}
        
        try:
            with open(self.cred_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return {}
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except InvalidToken:
            print(Fore.RED + "Invalid decryption key! Cannot decrypt credentials." + Fore.RESET)
            raise
        except json.JSONDecodeError:
            print(Fore.RED + "Corrupted credential file!" + Fore.RESET)
            return {}
        except Exception as e:
            print(Fore.RED + f"Error loading credentials: {e}" + Fore.RESET)
            raise
    
    def _save_credentials(self, credentials: dict):
        """
        Encrypt and save credentials to file
        
        Args:
            credentials: Dictionary of credentials to save
        """
        try:
            json_bytes = json.dumps(credentials, indent=2).encode('utf-8')
            encrypted_data = self.fernet.encrypt(json_bytes)
            
            with open(self.cred_file, 'wb') as f:
                f.write(encrypted_data)
            
            print(f"\n{Fore.GREEN}✓ Credentials successfully saved to {self.cred_file}{Fore.RESET}")
        except Exception as e:
            print(Fore.RED + f"Error saving credentials: {e}" + Fore.RESET)
            raise
    
    def encrypt(self, action: str):
        """
        Encrypt and save credentials (create new or update existing)
        
        Args:
            action: Either 'add' or 'delete'
        """
        # Generate new key for encryption
        self._generate_key()
        
        # Load existing credentials if file exists
        if self.cred_file.exists():
            try:
                key_input = input(Fore.GREEN + "Enter existing decryption key to modify credentials: " + Fore.RESET)
                if not self._load_key(key_input):
                    print(Fore.RED + "Cannot modify credentials without valid key!" + Fore.RESET)
                    return
                credentials = self._load_credentials()
            except InvalidToken:
                print(Fore.RED + "Invalid key! Cannot access existing credentials." + Fore.RESET)
                return
        else:
            credentials = {}
        
        # Perform the requested action
        if action == 'add':
            self._add_credentials(credentials)
        elif action == 'delete':
            self._delete_credentials(credentials)
        
        # Save the updated credentials with new key
        self._save_credentials(credentials)
        
        # Display the new key
        self._display_key()
    
    def _add_credentials(self, credentials: dict):
        """Add new credentials interactively"""
        print(f"\n{Fore.CYAN}--- Add New Credentials ---{Fore.RESET}")
        
        while True:
            choice = input("Enter 'yes' to add an account or 'no' to quit: ").lower()
            
            if choice == 'yes':
                username = input("  Username: ").strip()
                if not username:
                    print(Fore.RED + "  Username cannot be empty!" + Fore.RESET)
                    continue
                
                password = input("  Password: ").strip()
                if not password:
                    print(Fore.RED + "  Password cannot be empty!" + Fore.RESET)
                    continue
                
                credentials[username] = password
                print(Fore.GREEN + f"  ✓ Added credential for '{username}'" + Fore.RESET)
                
            elif choice == 'no':
                break
            else:
                print(Fore.RED + "  Please enter 'yes' or 'no'" + Fore.RESET)
    
    def _delete_credentials(self, credentials: dict):
        """Delete credentials interactively"""
        if not credentials:
            print(Fore.YELLOW + "No credentials to delete!" + Fore.RESET)
            return
        
        print(f"\n{Fore.CYAN}--- Available Credentials ---{Fore.RESET}")
        for username in credentials.keys():
            print(f"  • {username}")
        
        account = input("\nEnter the account username to remove: ").strip()
        
        if account in credentials:
            del credentials[account]
            print(Fore.GREEN + f"✓ Deleted credential for '{account}'" + Fore.RESET)
        else:
            print(Fore.RED + f"Account '{account}' not found!" + Fore.RESET)
    
    def decrypt(self, key_input: str = None) -> dict:
        """
        Decrypt and return credentials
        
        Args:
            key_input: Optional encryption key (will prompt if not provided)
            
        Returns:
            dict: Decrypted credentials
        """
        if not self.cred_file.exists():
            print(Fore.RED + f"Credential file '{self.cred_file}' does not exist!" + Fore.RESET)
            return {}
        
        # Get key if not provided
        if key_input is None:
            key_input = input(Fore.GREEN + "Enter your decryption key: " + Fore.RESET)
        
        if not self._load_key(key_input):
            return {}
        
        try:
            return self._load_credentials()
        except InvalidToken:
            print(Fore.RED + "Decryption failed! Invalid key or corrupted file." + Fore.RESET)
            return {}
    
    def show_credentials(self, key_input: str = None):
        """Display decrypted credentials"""
        credentials = self.decrypt(key_input)
        
        if not credentials:
            print(Fore.YELLOW + "\nNo credentials to display!" + Fore.RESET)
            return
        
        print(f"\n{Fore.CYAN}{'='*50}{Fore.RESET}")
        print(f"{Fore.YELLOW}Credentials List ({len(credentials)} entries){Fore.RESET}")
        print(f"{Fore.CYAN}{'='*50}{Fore.RESET}")
        
        for idx, (username, password) in enumerate(credentials.items(), 1):
            print(f"{Fore.GREEN}[{idx}]{Fore.RESET} {Fore.CYAN}{username}:{Fore.RESET} {password}")
        
        print(f"{Fore.CYAN}{'='*50}{Fore.RESET}\n")
    
    def _display_key(self):
        """Display the encryption key to the user"""
        print(f"\n{Fore.YELLOW}{'='*60}{Fore.RESET}")
        print(f"{Fore.RED}⚠ IMPORTANT - Save this key!{Fore.RESET}")
        print(f"{Fore.YELLOW}{'='*60}{Fore.RESET}")
        print(f"{Fore.GREEN}Your encryption key is:{Fore.RESET}")
        print(f"{Fore.BLUE}{self.key.decode('utf-8')}{Fore.RESET}")
        print(f"{Fore.YELLOW}Keep this key safe! You'll need it to decrypt your credentials.{Fore.RESET}")
        print(f"{Fore.YELLOW}{'='*60}{Fore.RESET}\n")
    
    @staticmethod
    def display_banner(action: str):
        """Display ASCII art banner for the action"""
        banners = {
            'encrypt': Fore.YELLOW + r"""
******************************************************************************
*  _____                             _     ____                     _        *
* | ____|_ __   ___ _ __ _   _ _ __ | |_  / ___|  ___  ___ _ __ ___| |_ ___  *
* |  _| | '_ \ / __| '__| | | | '_ \| __| \___ \ / _ \/ __| '__/ _ \ __/ __| *
* | |___| | | | (__| |  | |_| | |_) | |_   ___) |  __/ (__| | |  __/ |_\__ \ *
* |_____|_| |_|\___|_|   \__, | .__/ \__| |____/ \___|\___|_|  \___|\__|___/ *
*                        |___/|_|                                            *
******************************************************************************
""",
            'decrypt': Fore.YELLOW + r"""
*****************************************************************************
*  ____                             _     ____                     _        *
* |  _ \  ___  ___ _ __ _   _ _ __ | |_  / ___|  ___  ___ _ __ ___| |_ ___  *
* | | | |/ _ \/ __| '__| | | | '_ \| __| \___ \ / _ \/ __| '__/ _ \ __/ __| *
* | |_| |  __/ (__| |  | |_| | |_) | |_   ___) |  __/ (__| | |  __/ |_\__ \ *
* |____/ \___|\___|_|   \__, | .__/ \__| |____/ \___|\___|_|  \___|\__|___/ *
*                       |___/|_|                                            *
*****************************************************************************
"""
        }
        
        banner_key = 'encrypt' if action != 'show' else 'decrypt'
        print(banners.get(banner_key, ""))


def main():
    """Main entry point for the credential manager"""
    parser = argparse.ArgumentParser(
        description="Secure Credential Manager with Fernet Encryption",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --f mycreds.db --action show
  %(prog)s --f mycreds.db --action add
  %(prog)s --f mycreds.db --action delete
        """
    )
    
    parser.add_argument(
        '--action',
        help="Action to perform",
        choices=['show', 'add', 'delete'],
        default='show'
    )
    
    parser.add_argument(
        '--f',
        help="Credential filename (will be stored in ~/pyenv3.9/secrets/)",
        type=str,
        required=True
    )
    
    parser.add_argument(
        '--key',
        help="Decryption key (for show action, if not provided will prompt)",
        type=str,
        default=None
    )
    
    parser.add_argument(
        '--path',
        help="Custom base path for credential storage",
        type=str,
        default=None
    )
    
    args = parser.parse_args()
    
    # Set custom path if provided
    base_path = Path(args.path) if args.path else None
    
    # Initialize credential manager
    manager = CredentialManager(args.f, base_path)
    
    # Display banner
    manager.display_banner(args.action)
    
    try:
        # Perform the requested action
        if args.action == 'show':
            manager.show_credentials(args.key)
        elif args.action in ['add', 'delete']:
            manager.encrypt(args.action)
        else:
            print(Fore.RED + f"Unknown action: {args.action}" + Fore.RESET)
            parser.print_help()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user.{Fore.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Fore.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()

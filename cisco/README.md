# The scripts automate rotation of locally configured admin accounts and enable secrets on Cisco devices

# Supported Devices
- Cisco IOS
- Cisoc IOS-XE
- Cisco NX-OS

# File Structure
<pre>
  pyenv3.9
  |-- data
      |-- cisco-local-adm_test.yaml      # Device YAML file
      |-- myCredentials.bin              # Encrypted admin password and enable secret
  |-- logs
  |-- templates
      |-- cisco_local_admin_template.j2  # Configuration template
  |-- cisco_rotate_admin.py              # Main rotation script
  |-- encrypt_credentials.py             # Script to generate cryption key and create encrypted credentials
</pre>

# Work Flows
1. Generate an encryption key and create an encrypted credential file by running "encrypt_credentials.py script"
2. Run the main rotation script "cisco_rotate_admin.py" to rotate admin accounts and enable secrets.

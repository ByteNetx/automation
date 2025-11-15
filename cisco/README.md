# The scripts automate rotation of locally configured admin accounts and enable secrets on Cisco devices

# Supported Devices
- Cisco IOS
- Cisoc IOS-XE
- Cisco NX-OS

# File Structure
<pre>
  pyenv3.9
  |-- data
      |-- cisco-local-adm_test.yaml
      |-- myCredentials.bin
  |-- logs
  |-- templates
      |-- cisco_local_admin_template.j2
  |-- cisco_rotate_admin.py
  |-- encrypt_credentials.py
</pre>

# Work Flows
1. Generate an encryption key and create an encrypted credential file by running "encrypt_credentials.py script"
2. Run the main rotation script "cisco_rotate_admin.py" to rotate admin accounts and enable secrets.

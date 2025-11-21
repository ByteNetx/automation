# Automation rotating locally configured admin accounts and enable secrets on Cisco devices

# Supported Devices
- Cisco IOS
- Cisoc IOS-XE
- Cisco NX-OS (10.3(1)F or above)

# File Structure
<pre>
  pyenv3.9
  |-- cisco
      |-- data
          |-- cisco-local-adm_test.yaml      # Device YAML file
          |-- cisco_credentials.bin          # Encrypted admin password and enable secret
      |-- logs
      |-- templates
          |-- cisco_local_admin_template.j2  # Configuration template
      |-- cisco_rotate_admin.py              # Main rotation script
      |-- password_hash.py                   # Module converting to cisco type 8/9 secret
      |-- encryption.py                      # Script to encrypt credentials
</pre>


Run the main rotation script "cisco_rotate_admin.py" to rotate admin accounts and enable secrets.

# Automation rotating locally configured admin accounts and enable secrets on Cisco devices

# Supported Devices
- Cisco IOS
- Cisoc IOS-XE
- Cisco NX-OS (10.3(1)F or above)

# File Structure
<pre>
  pyenv3.9
  |-- data
      |-- cisco-local-adm_test.yaml      # Device YAML file
  |-- logs
  |-- templates
      |-- cisco_local_admin_template.j2  # Configuration template
  |-- cisco_rotate_admin.py              # Main rotation script
  |-- hash_type9.py                      # Module converting to cisco type 9 secret
</pre>


Run the main rotation script "cisco_rotate_admin.py" to rotate admin accounts and enable secrets.

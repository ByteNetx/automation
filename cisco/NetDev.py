from netmiko import ConnectHandler
from netmiko import NetmikoTimeoutException
from netmiko import NetmikoAuthenticationException

class NetworkDevice:
    def __init__(self, host, username, password, secret, device_type):
        """
        Initializes connection with device parameters and prepares for connection.
        """
        self.device = {
            'host': host,
            'username': username,
            'password': password,
            'secret': secret,
            'device_type': device_type,
        }
        self.connection = None

    def connect(self):
        """
        Establishes the SSH connection to the network device.
        """
        try:
            print(f"Connecting to {self.device['host']}...")
            self.connection = ConnectHandler(**self.device)
            print("Connection established successfully!")
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as error:
            print(f"❌ Failed to SSH to {self.device['host']} with the below error:\n{error}")

    def show(self, command, **kwargs):
        """
        Sends a show command to the device and returns the output.
        """
        if self.connection:
            output = self.connection.send_command(command, **kwargs)
            return output
        else:
            return "Error: No active connection."
    
    def push_config(self, config_set, **kwargs):
        """
        Push config to the device and returns the output.
        """
        if self.connection:
            if '>' in self.connection.find_prompt():
                self.connection.enable()
            output = self.connection.send_config_set(config_set, **kwargs)
            return output
        else:
            return "Error: No active connection."

    def disconnect(self):
        """
        Safely closes the SSH session.
        """
        if self.connection:
            print(f"Disconnecting from {self.device['host']}...")
            self.connection.disconnect()
            self.connection = None

if __name__ == "__main__":
    pano = NetworkDevice(
        '192.168.10.254',
        'username',
        'passwd',
        'secret',
        'paloalto_panos'
    )

    pano.connect()
    cmd = 'show service | match 443$\\|8080$\\|3389$'
    pano.show('set cli pager off', expect_string=r'>', delay_factor=4)
    pano.show('set cli config-output-format set', expect_string=r'>', delay_factor=4)
    pano.show('configure', expect_string=r'#', delay_factor=4)
    resp = pano.show(cmd)

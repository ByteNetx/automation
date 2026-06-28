import xml.etree.ElementTree as ET
from requests import request,packages, Response
from requests.exceptions import SSLError, HTTPError, Timeout, TooManyRedirects

class PaloAltoAPI:

    def __init__(self, host: str, username: str=None, password: str=None, api_key: str=None):

        self.host = host
        self.username = username
        self.password = password
        if not api_key:
            self.key = self.get_api_key()
        else:
            self.key = api_key

    def _make_request(self, values, verify=False, timeout=300) -> Response:

        packages.urllib3.disable_warnings()

        url = f'https://{self.host}/api'

        try:

            req_type = values['type']
            params = values['params']
            headers = values['headers']
            ver = verify
            time = timeout

        except KeyError as err:
            print(f'Expected 3 values, missing one or more: {err}')
            return None

        try:

            req = request(
                req_type,
                url=url,
                headers=headers,
                params=params,
                verify=ver,
                timeout=time
            )

            req.raise_for_status()
            return req

        except (SSLError, Timeout, ConnectionError, TooManyRedirects) as err:
            print(f'API call failed due to {err}')
            return req

    def get_api_key(self):
        '''
        Returns API key for specified user/password

        :param host: String containing device hostname/address
        :param username: Username string
        :param password: Password string
        :return: API Key
        '''

        values = {
            'type': 'POST',
            'params': {
                'type': 'keygen',
                'user': self.username,
                'password': self.password
            },
            'headers': None
        }

        data = self._make_request(values)
        root = ET.fromstring(data.text)
        api_key = root.find('./result/key').text
        return api_key

def parse_arguments():
    import getpass
    import argparse
    """Parse command line arguments."""
    class Password(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser(
        description="Create PANOS API Key"
    )
    
    # Connection arguments
    parser.add_argument("--hostname", "-H", type=str, required=True,
                        help="Panorama hostname or IP address")
    parser.add_argument("--username", "-u", type=str, required=True,
                        help="Panorama admin username")
    parser.add_argument("--password", "-p", action=Password, nargs='?', dest='passwd', required=True,
                        help="Panorama admin password")

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    PAN_HOST = args.hostname
    PAN_USERNAME = args.username
    PAN_PASSWORD = args.passwd
    pan = PaloAltoAPI(
        host=PAN_HOST,
        username=PAN_USERNAME,
        password=PAN_PASSWORD
    )
    print(pan.key)

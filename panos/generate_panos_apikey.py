import requests, xmltodict, argparse, getpass

def getAPIKey(panLogin):
    requests.packages.urllib3.disable_warnings()
    try:
        # get API key from PANOS
        data = {
            'type': 'keygen',
            'user': panLogin['username'],
            'password': panLogin['password']
        }
        getAPIKeyRequest = requests.post(f"https://{panLogin['host']}/api/", data=data, verify=False)
        getAPIKeyRequest.raise_for_status()
        apiKeyDict = xmltodict.parse(getAPIKeyRequest.content)
        apiKey = apiKeyDict['response']['result']['key']
        return apiKey
    except (requests.exceptions.HTTPError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        return f"Failed to generate API key from {panLogin['host']} due to {e}\n"
    
def runner():
    class PASSWORD(argparse.Action):
        def __call__(self, parser, namespace, values, option_string):
            if values is None:
                values = getpass.getpass()
            setattr(namespace, self.dest, values)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--host', help='Hostname or IP of PANOS', type=str, required=True
    )
    parser.add_argument(
        '--u', help='Username of API account', type=str, required=True
    )
    parser.add_argument(
        '--p', help='Password of API account', action=PASSWORD, nargs='?', dest='password', required=True
    )
    args = parser.parse_args()

    panLogin = {
            'host': args.host,
            'username': args.u,
            'password': args.password
        }
    apiKey = getAPIKey(panLogin)
    print(f"############## API key for {args.u} ##############\n{apiKey}")

if __name__ == "__main__":
    runner()

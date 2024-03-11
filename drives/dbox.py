from dotenv import dotenv_values, load_dotenv
import os, requests
from dropbox import DropboxOAuth2FlowNoRedirect

current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
dotenv_path = os.path.join(parent_dir, '.env')
load_dotenv(dotenv_path)


def gen_auth_url(csrf):
    client_id = os.getenv('DROPBOX_CLIENT_ID')
    dropbox_redirect_uri = os.getenv('DROPBOX_REDIRECT_URI')
    dropbox_state = csrf
    auth_url = f"https://www.dropbox.com/oauth2/authorize?client_id={client_id}&redirect_uri={dropbox_redirect_uri}&response_type=code&token_access_type=offline&force_reapprove=true&state={dropbox_state}"
    return auth_url

def getAccessToken(code):
    app_key = os.getenv('DROPBOX_APP_KEY')
    app_secret = os.getenv('DROPBOX_APP_SECRET')
    response = requests.post('https://api.dropboxapi.com/oauth2/token', params={
        'code': code,
        'grant_type': 'authorization_code',
        'client_id': app_key,
        'client_secret': app_secret,
        'redirect_uri': os.getenv('DROPBOX_REDIRECT_URI')
    })
    return response.json()
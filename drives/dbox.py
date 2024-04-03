from dotenv import load_dotenv
import os, requests
from dropbox import Dropbox
from dropbox.files import WriteMode

current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
dotenv_path = os.path.join(parent_dir, '.env')
load_dotenv(dotenv_path)

app_key = os.getenv('DROPBOX_APP_KEY')
app_secret = os.getenv('DROPBOX_APP_SECRET')
redirect_uri = os.getenv('DROPBOX_REDIRECT_URI')

def gen_auth_url(csrf):
    dropbox_redirect_uri = os.getenv('DROPBOX_REDIRECT_URI')
    print(dropbox_redirect_uri)
    dropbox_state = csrf
    auth_url = f"https://www.dropbox.com/oauth2/authorize?client_id={app_key}&redirect_uri={dropbox_redirect_uri}&response_type=code&token_access_type=offline&force_reapprove=true&state={dropbox_state}"
    return auth_url

def getAccessToken(code):
    response = requests.post('https://api.dropboxapi.com/oauth2/token', params={
        'code': code,
        'grant_type': 'authorization_code',
        'client_id': app_key,
        'client_secret': app_secret,
        'redirect_uri': redirect_uri
    })
    return response.json()

def refresh_access_token(refresh_token):
    response = requests.post('https://api.dropboxapi.com/oauth2/token', params={
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
        'client_id': app_key,
        'client_secret': app_secret
    })
    print(response.json())
    return response.json()["access_token"]

def get_drive(refresh_token):
    access_token = refresh_access_token(refresh_token)
    dbx = Dropbox(oauth2_access_token=access_token)
    user = dbx.users_get_current_account()
    usage = dbx.users_get_space_usage()
    user = {
        "id": user.account_id,
        "name": user.name.display_name,
        "email": user.email,
        "total": usage.allocation.get_individual().allocated,
        "usage": usage.used
    }
    user.update({"brand": "Dropbox"})
    user.update({"available": user['usage'] - user['total']})
    return user

def upload(file_id, file_name, refresh_token):
    access_token = refresh_access_token(refresh_token)
    dbx = Dropbox(oauth2_access_token=access_token)
    with open(f'uploads/{file_id}/{file_name}', 'rb') as f:
        uploaded_file = dbx.files_upload(f.read(), f'/{file_name}', mode=WriteMode('overwrite'))
    file_metadata = {
        "name": uploaded_file.name,
        "size": uploaded_file.size,
        "path": uploaded_file.path_display,
        "link": dbx.sharing_create_shared_link(uploaded_file.path_display).url,
        "id": uploaded_file.id}
    return file_metadata

def download_file(file_name, refresh_token):
    access_token = refresh_access_token(refresh_token)
    dbx = Dropbox(oauth2_access_token=access_token)
    metadata, res = dbx.files_download(path=f'/{file_name}')
    return res.content
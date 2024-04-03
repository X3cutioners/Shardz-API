from boxsdk import OAuth2, Client
from dotenv import dotenv_values, load_dotenv
import os, requests

current_dir = os.path.dirname(os.path.realpath(__file__))
parent_dir = os.path.dirname(current_dir)
dotenv_path = os.path.join(parent_dir, '.env')
load_dotenv(dotenv_path)

def gen_auth_url(csrf):
    client_id = os.getenv('BOX_CLIENT_ID')
    box_redirect_uri = os.getenv('BOX_REDIRECT_URI')
    box_state = csrf
    auth_url = f"https://account.box.com/api/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={box_redirect_uri}&state={box_state}"
    return auth_url

def get_drive(access_token):
    oauth = OAuth2(
        client_id= os.getenv('BOX_CLIENT_ID'),
        client_secret= os.getenv('BOX_CLIENT_SECRET'),
        access_token= access_token,
        store_tokens= lambda access_token, refresh_token: None,
        )
    client = Client(oauth)
    user = client.user().get()
    user_json = user.response_object
    user_json['brand'] = 'Box'
    user_json['available'] = user_json['space_amount'] - user_json['space_used']
    return user_json

def getAccessToken(code):
    oauth = OAuth2(
        client_id= os.getenv('BOX_CLIENT_ID'),
        client_secret= os.getenv('BOX_CLIENT_SECRET'),
        store_tokens= lambda access_token, refresh_token: None,
        )
    access_token, refresh_token = oauth.authenticate(code)
    drive_data = get_drive(access_token)
    response = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "drive_id": drive_data['id']
    }
    return response

def refresh_access_token(refresh_token):
    data = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token,
        'client_id': os.getenv('BOX_CLIENT_ID'),
        'client_secret': os.getenv('BOX_CLIENT_SECRET')
    }
    response = requests.post('https://api.box.com/oauth2/token', data=data)
    new_tokens = {
        "access_token": response.json()['access_token'],
        "refresh_token": response.json()['refresh_token']
    }
    return new_tokens

def upload(file_id, file_name, access_token, refresh_token):
    oauth = OAuth2(
        client_id= os.getenv('BOX_CLIENT_ID'),
        client_secret= os.getenv('BOX_CLIENT_SECRET'),
        access_token= access_token,
        refresh_token= refresh_token,
        store_tokens= lambda access_token, refresh_token: None,
        )
    client = Client(oauth)
    folder_id = 0
    user = client.user().get().response_object
    return user
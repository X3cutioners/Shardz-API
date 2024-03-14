import string, random, os, send_email, requests, json
from argon2 import PasswordHasher
from supabase import create_client, Client
from imagekitio import ImageKit
from dotenv import dotenv_values
from drives import box, dbox

# Load Environment Variables
envs = dotenv_values(".env")

# Environment Variables
url: str = envs.get("SUPABASE_URL")
key: str = envs.get("SUPABASE_KEY")
private_key: str = envs.get("IMAGEKIT_PRIVATE_KEY")
public_key: str = envs.get("IMAGEKIT_PUBLIC_KEY")
url_endpoint: str = envs.get("IMAGEKIT_URL_ENDPOINT")
ipapi_key: str = envs.get("IPAPI_KEY")

# ImageKit SDK initialization
imagekit = ImageKit(private_key=private_key, public_key=public_key, url_endpoint=url_endpoint)

# Argon2 Password Hasher
ph = PasswordHasher()

# Supabase SDK initialization
supabase: Client = create_client(url, key)

####################################################
# Shardz Account Management System
####################################################

def generate_token(n):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

def get_location(ip_addr):
    response = requests.get(f"https://api.ipapi.is/?q={ip_addr}&key={ipapi_key}")
    data = response.json()
    location = f"Location: {data['location']['city']}, {data['location']['state']}, {data['location']['country']}\n\nISP: {data['asn']['org']}"
    return location

def login(email, password):
    user = supabase.table('users').select("*").eq('email', email).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        try: 
            ph.verify(user['password'], password)
            access_token = generate_token(16)
            supabase.table('users').update({"access_token": access_token}).eq('email', email).execute()
            return access_token
        except:
            return None

def register(name, email, password):
    user = supabase.table('users').select("*").eq('email', email).execute()
    if len(user.data) == 0:
        hashed_password = ph.hash(password)
        verification_token = generate_token(30)
        access_token = generate_token(16)
        print(verification_token)
        send_email.send_verification_email(name, email, verification_token)
        supabase.table('users').insert({"name": name, "email": email, "password": hashed_password, "verification": verification_token, "access_token": access_token}).execute()
        return True
    else:
        return None

def forgot_password(email, ip_addr):
    user = supabase.table('users').select("*").eq('email', email).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        verification_token = generate_token(30)
        ip2l = get_location(ip_addr)
        send_email.send_password_reset_email(user['name'], email, verification_token, ip2l)
        supabase.table('users').update({"verification": verification_token}).eq('email', email).execute()
        return True

def verify_email(token):
    user = supabase.table('users').select("*").eq('verification', token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        access_token = generate_token(16)
        supabase.table('users').update({"verification": "verified", "access_token": access_token}).eq('verification', token).execute()
        return access_token

def update_profile(access_token, name, email, file):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        if file:
            file.save("profile.jpg")
            response = imagekit.upload_file(file = open("profile.jpg", "rb"), file_name = "profile.jpg")
            os.remove("profile.jpg")
            profile_picture_url = response.response_metadata.raw['url']
        supabase.table('users').update({"name": name, "email": email, "profile_picture": profile_picture_url}).eq('access_token', access_token).execute()
        return True
    
def update_password(access_token, new_password):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        hashed_password = ph.hash(new_password)
        supabase.table('users').update({"password": hashed_password}).eq('access_token', access_token).execute()
        return True

def get_profile(access_token):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        return user
    
def dashboard(access_token):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        json_data = open("dashboard.json", "r").read()
        json_data = json.loads(json_data)
        return json_data

####################################################
# Shardz Drives Management System
####################################################

def add_storage(access_token):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        csrf = generate_token(16)
        supabase.table('users').update({"csrf_drive": csrf}).eq('access_token', access_token).execute()
        storage_oauth = []
        box_oauth = box.gen_auth_url(csrf)
        dropbox_oauth = dbox.gen_auth_url(csrf)
        box_oauth_url = {
            "drive": "box",
            "url": box_oauth
        }
        dropbox_oauth_url = {
            "drive": "dropbox",
            "url": dropbox_oauth
        }
        storage_oauth.append(box_oauth_url)
        storage_oauth.append(dropbox_oauth_url)
        return storage_oauth
    
def if_exists(csrf, drive_unique_id):
    user = supabase.table('users').select("*").eq('csrf_drive', csrf).execute()
    if len(user.data) == 0:
        return None
    else:
        drives = user.data[0]['drives']
        for drive in drives:
            if drive['drive_unique_id'] == drive_unique_id:
                return True
        return False

def oauth_callback(code, csrf, drive):
    user = supabase.table('users').select("*").eq('csrf_drive', csrf).execute()
    if len(user.data) == 0:
        return None
    else:
        drive_data = user.data[0]['drives']
        if drive == "box":
            drive_data = box.getAccessToken(code)
            if if_exists(csrf, drive_data['id']):
                return False
            else:
                drive_json = {
                    "id": len(drive_data) + 1,
                    "drive_unique_id": drive_data['drive_id'],
                    "drive_name": "Box",
                    "access_token": drive_data['access_token'],
                    "refresh_token": drive_data['refresh_token']
                }
                drive_data.append(drive_json)
                supabase.table('users').update({"drives": drive_data}).eq('csrf_drive', csrf).execute()
                return True
            
        elif drive == "dropbox":
            drive_data = dbox.getAccessToken(code)
            if if_exists(csrf, drive_data['uid']):
                return False
            else:
                drive_json = {
                    "id": len(drive_data) + 1,
                    "drive_unique_id": drive_data['uid'],
                    "drive_name": "Dropbox",
                    "access_token": drive_data['access_token'],
                    "refresh_token": drive_data['refresh_token']
                }
                drive_data.append(drive_json)
                supabase.table('users').update({"drives": drive_data}).eq('csrf_drive', csrf).execute()
                return True
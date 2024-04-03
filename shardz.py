import string, random, os, send_email, requests, shutil, csv
from drives import box, dbox
from argon2 import PasswordHasher
from supabase import create_client, Client
from imagekitio import ImageKit
from dotenv import dotenv_values
from filesplit.split import Split
from filesplit.merge import Merge
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
        send_email.send_verification_email(name, email, verification_token)
        supabase.table('users').insert({"name": name, "email": email, "password": hashed_password, "verification": verification_token, "access_token": access_token, "files": {"files": []}, "drives": {"drives": []}}).execute()
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

def update_box_token(email, refresh_token, drive_id):
    user = supabase.table('users').select("*").eq('email', email).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        drives = user['drives']['drives']
        for drive in drives:
            if str(drive['id']) == str(drive_id):
                drive['refresh_token'] = str(refresh_token)
                drive_data = {"drives": drives}
                response = supabase.table('users').update({"drives": drive_data}).eq('email', email).execute()
                return True
        return None

def dashboard(access_token):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        files = user['files']['files']
        drives = user['drives']['drives']
        main_drives = {"dropbox": {
            "drive_name": "Dropbox",
            "drive_logo": "https://ik.imagekit.io/shardz/icons/dropbox.png",
            "used": 0,
            "total": 0
        }, "box": {
            "drive_name": "Box",
            "drive_logo": "https://ik.imagekit.io/shardz/icons/box.png",
            "used": 0,
            "total": 0
        }}
        for drive in drives:
            if drive['drive_name'] == "Box":
                new_tokens = box.refresh_access_token(drive['refresh_token'])
                access_token = new_tokens['access_token']
                refresh_token = new_tokens['refresh_token']
                drive_id = drive['id']
                update_box_token(user['email'], refresh_token, drive_id)
                drive_info = box.get_drive(access_token)
                main_drives['box']['used'] += drive_info['space_used']
                main_drives['box']['total'] += drive_info['space_amount']
            elif drive['drive_name'] == "Dropbox":
                drive_info = dbox.get_drive(drive['refresh_token'])
                main_drives['dropbox']['used'] += drive_info['usage']
                main_drives['dropbox']['total'] += drive_info['total']
        json_data = {
            "files": files,
            "drives": main_drives
        }
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
        response = supabase.table('users').update({"csrf_drive": csrf}).eq('access_token', access_token).execute()
        storage_oauth = []
        box_oauth = box.gen_auth_url(csrf)
        dropbox_oauth = dbox.gen_auth_url(csrf)
        box_oauth_url = {
            "drive": "box",
            "url": box_oauth,
            "logo": "https://ik.imagekit.io/shardz/icons/box.png"
        }
        dropbox_oauth_url = {
            "drive": "dropbox",
            "url": dropbox_oauth,
            "logo": "https://ik.imagekit.io/shardz/icons/dropbox.png"
        }
        storage_oauth.append(box_oauth_url)
        storage_oauth.append(dropbox_oauth_url)
        return storage_oauth
    
## Checking if the Drive is already existing in the user's account

def if_exists(csrf, drive_unique_id):
    user = supabase.table('users').select("*").eq('csrf_drive', csrf).execute()
    if len(user.data) == 0:
        return None
    else:
        drives = user.data[0]['drives']['drives']
        if len(drives) == 0:
            return False
        for drive in drives:
            if drive['drive_unique_id'] == drive_unique_id:
                return True
        return False

def oauth_callback(code, csrf, drive):
    user = supabase.table('users').select("*").eq('csrf_drive', csrf).execute()
    if len(user.data) == 0:
        return None
    else:
        user_drive_data = user.data[0]['drives']['drives']
        if drive == "box":
            drive_data = box.getAccessToken(code)
            if if_exists(csrf, drive_data['drive_id']):
                return False
            else:
                drive_json = {
                    "id": len(drive_data) + 1,
                    "drive_unique_id": drive_data['drive_id'],
                    "drive_name": "Box",
                    "drive_logo": "https://ik.imagekit.io/shardz/icons/box.png",
                    "refresh_token": drive_data['refresh_token']
                }
                user_drive_data.append(drive_json)
                drive_data = {"drives": user_drive_data}
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
                    "drive_logo": "https://ik.imagekit.io/shardz/icons/dropbox.png",
                    "drive_name": "Dropbox",
                    "refresh_token": drive_data['refresh_token']
                }
                user_drive_data.append(drive_json)
                drive_data = {"drives": user_drive_data}
                supabase.table('users').update({"drives": drive_data}).eq('csrf_drive', csrf).execute()
                return True
def drives(access_token):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        if len(user['drives']['drives']) == 0:
            return 404
        return user['drives']['drives']

def get_drive(access_token, drive_id):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        drives = user['drives']['drives']
        for drive in drives:
            if str(drive['id']) == str(drive_id):
                if drive['drive_name'] == "Box":
                    new_tokens = box.refresh_access_token(drive['refresh_token'])
                    access_token = new_tokens['access_token']
                    refresh_token = new_tokens['refresh_token']
                    response = box.get_drive(access_token)
                    update_box_token(user['email'], refresh_token, drive_id)
                    return response
                elif drive['drive_name'] == "Dropbox":
                    response = dbox.get_drive(drive['refresh_token'])
                    return response
        return None

def get_all_drives(access_token):
    user = supabase.table('users').select("*").eq('access_token', access_token).execute()
    if len(user.data) == 0:
        return None
    else:
        user = user.data[0]
        drives = user['drives']['drives']
        all_drives = []
        for drive in drives:
            if drive['drive_name'] == "Box":
                new_tokens = box.refresh_access_token(drive['refresh_token'])
                access_token = new_tokens['access_token']
                refresh_token = new_tokens['refresh_token']
                update_box_token(user['email'], refresh_token, drive['id'])
                drive_info = box.get_drive(access_token)
                all_drives.append(drive_info)
            elif drive['drive_name'] == "Dropbox":
                drive_info = dbox.get_drive(drive['refresh_token'])
                all_drives.append(drive_info)
        return all_drives

# def upload(access_token, file):
#     user = supabase.table('users').select("*").eq('access_token', access_token).execute()
#     if len(user.data) == 0:
#         return None
#     else:
#         file_id = generate_token(10)
#         unique_filename = f'{file_id}.{file.filename.split(".")[-1]}'
#         with open(f'uploads/{unique_filename}', 'wb') as f:
#             f.write(file.read())
#         file_size = os.path.getsize(f'uploads/{unique_filename}')
#         os.mkdir(f'uploads/{file_id}')
#         all_drives = get_all_drives(access_token)
#         available_space = 0
#         for drive in all_drives:
#             if drive['brand'] == "Box":
#                 available_space += drive['space_amount'] - drive['space_used']
#             elif drive['brand'] == "Dropbox":
#                 available_space += drive['total'] - drive['usage']
#         if file_size > available_space:
#             return None
#         sorted_drives = sorted(all_drives, key=lambda x: x['available'])
#         Split(f'uploads/{unique_filename}', f'uploads/{file_id}').bysize(size=sorted_drives[0]['available'])
#         splitted_files = []
#         with open(f'uploads/{file_id}/manifest', 'r') as f:
#             files_data = f.readlines()
#             for file_data in files_data:
#                 file_dict = {
#                     "file_name": file_data.split(",")[0],
#                     "file_size": file_data.split(",")[1]
#                 }
#                 splitted_files.append(file_dict)
#         splitted_files = splitted_files[1:]
#         user = supabase.table('users').select("*").eq('access_token', access_token).execute()
#         drives = user.data[0]['drives']['drives']
#         print(drives)
#         box_token = ""
#         for file in splitted_files:
#             for drive in drives:
#                 if drive['drive_name'] == "Box":
#                     if box_token == "":
#                         new_tokens = box.refresh_access_token(drive['refresh_token'])
#                         auth_token = new_tokens['access_token']
#                         refresh_token = new_tokens['refresh_token']
#                         update_box_token(user.data[0]['email'], refresh_token, drive['id'])
#                     box.upload(file_id, file['file_name'], box_token, refresh_token)
#                 elif drive['drive_name'] == "Dropbox":
#                     dbox.upload(file_id, file['file_name'], drive['refresh_token'])
#         os.remove(f'uploads/{unique_filename}')
#         # shutil.rmtree(f'uploads/{file_id}')
#         return True
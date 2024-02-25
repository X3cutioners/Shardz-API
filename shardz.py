import string, random, os, send_email, requests
from argon2 import PasswordHasher
from supabase import create_client, Client
from imagekitio import ImageKit
from dotenv import dotenv_values

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
        supabase.table('users').update({"verification": "verified", "access_token": access_token}).eq('verification_token', token).execute()
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
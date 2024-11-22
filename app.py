import streamlit as st
import boto3
from botocore.config import Config
import os
import firebase_admin
from firebase_admin import credentials, auth
import requests
import json
import re

# Firebase Setup
FIREBASE_WEB_API_KEY = st.secrets["FIREBASE_WEB_API_KEY"]
FIREBASE_ADMIN_CREDENTIALS = st.secrets["FIREBASE_ADMIN_CREDENTIALS"]

if not firebase_admin._apps:
    cred = credentials.Certificate(json.loads(FIREBASE_ADMIN_CREDENTIALS))
    firebase_admin.initialize_app(cred)

# AWS S3 Setup
os.environ["AWS_ACCESS_KEY_ID"] = st.secrets["AWS_ACCESS_KEY_ID"]
os.environ["AWS_SECRET_ACCESS_KEY"] = st.secrets["AWS_SECRET_ACCESS_KEY"]
os.environ["AWS_REGION"] = st.secrets["AWS_REGION"]
s3_config = Config(signature_version='s3v4', region_name=os.environ["AWS_REGION"])
s3 = boto3.client('s3', config=s3_config)

bucket_name = "climate-ai-data-science-datasets"
prefix = "testing-MAE-tool/"

# Firebase Helper Functions
def valid_email(email):
    return re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email)

def register_user(email, password):
    try:
        user = auth.create_user(email=email, password=password)
        return True
    except Exception as e:
        st.error(f"Error during registration: {str(e)}")
        return False

def login_user(email, password):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    try:
        response = requests.post(url, json=payload)
        data = response.json()
        if "error" in data:
            st.error("Login failed: Invalid email or password.")
            return False
        st.session_state["user"] = data["email"]
        st.rerun()
        return True
    except Exception as e:
        st.error(f"Error during login: {str(e)}")
        return False

# S3 Helper Functions
def list_available_files():
    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if 'Contents' in response:
            files = [
                obj['Key'].replace(prefix, '') for obj in response['Contents']
                if obj['Key'].endswith('.png')
            ]
            return files
        else:
            return []
    except Exception as e:
        st.error(f"Error listing files: {e}")
        return []

def get_png_from_s3(region, timescale):
    file_name = f"{region}-{timescale}.png"
    file_key = f"{prefix}{file_name}"
    try:
        file_url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={'Bucket': bucket_name, 'Key': file_key},
            ExpiresIn=3600
        )
        return file_url
    except Exception as e:
        st.error(f"Error fetching PNG: {e}")
        return None

# Streamlit Authentication and Main App
st.title("MAE Tool ClimateAi")

if "user" not in st.session_state:
    # Login/Register Page
    menu = st.sidebar.selectbox("Select an option", ["Register", "Login"])

    if menu == "Register":
        st.subheader("Register")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Register"):
            if not valid_email(email):
                st.error("Invalid email address.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            else:
                if register_user(email, password):
                    st.success("Registration successful! Please log in.")
                else:
                    st.error("Registration failed.")

    elif menu == "Login":
        st.subheader("Login")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if login_user(email, password):
                st.success("Login successful!")
                # UI will automatically update based on session state
else:
    # Main App for Authenticated Users
    st.sidebar.write(f"Logged in as: {st.session_state['user']}")
    if st.sidebar.button("Logout"):
        st.session_state.pop("user")
        st.experimental_rerun()

    st.write("Select a region and timescale to view the PNG file.")
    available_files = list_available_files()

    if available_files:
        regions = sorted(set([file.split('-')[0] for file in available_files]))
        timescales = sorted(set([file.split('-')[1].replace('.png', '') for file in available_files]))

        region = st.selectbox("Select Region", regions)
        timescale = st.selectbox("Select Timescale", timescales)

        if st.button("Get PNG"):
            png_url = get_png_from_s3(region, timescale)
            if png_url:
                st.image(png_url, caption=f"{region} - {timescale}", use_container_width=True)
                st.write(f"[Download PNG]({png_url})")
    else:
        st.warning("No PNG files found in the S3 bucket.")

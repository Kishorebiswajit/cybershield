import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "cybershield-dev-key-change-in-prod")
    DEBUG = os.getenv("DEBUG", "True") == "True"
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")

from dotenv import load_dotenv
import os

load_dotenv()
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '1234')  # Updated environment variable name
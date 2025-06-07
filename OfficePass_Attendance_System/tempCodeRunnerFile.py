from dotenv import load_dotenv
import os

load_dotenv()
ADMIN_PASSWORD = os.getenv('admin','1234')
# Encrypted File Vault

A secure, cloud-based file storage web application using custom AES-GCM encryption and Cloudinary for file hosting. This system ensures that files are encrypted before upload, securely stored, and can only be decrypted by authenticated users.

## Features

-  **User Authentication** (Register/Login)
-  **Custom AES-GCM Encryption** with key-dependent dynamic S-Box
-  **Cloudinary Integration** for encrypted file storage
-  **Decryption Logs**: Tracks who decrypted which file and when
-  **Upload & Decryption History** per user
-  Chunk-wise encryption for enhanced avalanche effect

## 🛠️ Tech Stack

- **Backend**: Python Flask  
- **Frontend**: HTML, CSS, JavaScript 
- **Encryption**: AES-GCM + Key-dependent S-Box  
- **Database**: SQLite  
- **Cloud Storage**: Cloudinary  
- **Session Management**: Flask-Login  

## 📁 Folder Structure
encrypted_file_vault_folder/
│
├── app.py # Main Flask app
├── cloudinary_utils.py # Cloudinary file handling
├── encryption_utils.py # Encryption/decryption logic
├── create_db.py # Initializes SQLite DB
├── users.db # SQLite DB file
├── logs.txt # Local log file for decryption activity
├── requirements.txt # Required Python libraries
├── .env # Environment variables (Cloudinary credentials)
│
├── templates/ # HTML templates
├── static/ # CSS and frontend assets
└── decrypted_output/ # Stores decrypted files locally


## ⚙️ Setup Instructions

1. **Install dependencies**

     pip install -r requirements.txt

3. **Set up environment variables**

     Create a .env file in the root folder with the following content:

     CLOUDINARY_CLOUD_NAME=your_cloud_name

     CLOUDINARY_API_KEY=your_api_key

     CLOUDINARY_API_SECRET=your_api_secret

     SECRET_KEY=your_flask_secret
5. **Initialize the database**

     python create_db.py
7. **Run the app**

     python app.py
   
Visit http://localhost:5000 in your browser.

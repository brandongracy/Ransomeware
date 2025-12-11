#!/usr/bin/env python3 

from cryptography.fernet import Fernet
import os, time, math
import tkinter as tk
from PIL import Image, ImageTk
import urllib.request
import io

def write_key():
    # generates a key and save it into a file
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    # load the key from the current directory named 'key.key'
    return open("key.key", "rb").read()


def if_key():
    if os.path.exists("key.key"):
        print("Key found. Loading...")
        return load_key()
    else:
        print("Key not found. Create a new...")
        write_key()
        return load_key()



def encrypt_message(message):
    key = if_key()
    f = Fernet(key)
    message_bytes = message.encode()
    print("Plaintext is:", message)
    encrypted = f.encrypt(message_bytes)
    print("ciphertext is:", encrypted.decode('utf-8'))
    with open("message_encrypted.txt", "wb") as file:
        file.write(encrypted)
    return encrypted
#msg = input("Enter message to encrypt: ")
#ciphertext = encrypt_message(msg)


def decrypt_message(encrypted):
    key = if_key()
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    print("Decrypted text:", decrypted.decode('utf-8'))
    return decrypted
#decrypt_message(ciphertext)

def encrypt_file(File_path):
    key = if_key()
    fernet = Fernet(key)
    with open(File_path, "rb") as file:
        content = file.read()
    content_encrypted = fernet.encrypt(content)
    with open(File_path + ".encrypted", "wb") as file:
        file.write(content_encrypted)
    print("encrypted!")


def decrypt_file(File_path):
    key = if_key()
    fernet = Fernet(key)
    with open(File_path, "rb") as file:
        content_encrypted = file.read()
    content_original = fernet.decrypt(content_encrypted)
    #output_path = file_path.replace(".rncrypted", "")
    with open(File_path, "wb") as file:
        file.write(content_original)
    print("File Decrypted successfully: ")

def display_ransomware_image():
    """
    Displays the Wana Decrypt0r 2.0 ransomware image.
    This is for educational purposes only.
    """
    try:
        import ssl
        import threading

        def show_image():
            # Disable SSL verification for downloading the image
            ssl._create_default_https_context = ssl._create_unverified_context

            try:
                # Create a hidden root window
                root = tk.Tk()
                root.withdraw()

                # Create a new window to display the image
                image_window = tk.Toplevel(root)
                image_window.title("ENCRYPTION TOOL - Educational Reference")
                image_window.geometry("1000x700")
                image_window.configure(bg="black")
                image_window.attributes('-topmost', True)  # Keep window on top

                # URL of the Wana Decrypt0r 2.0 ransomware image
                image_url = "https://www.secpod.com/blog/wp-content/uploads/2017/05/Screenshot-from-2017-05-14-23-42-20.png"

                # Download the image
                print("[*] Downloading Wana Decrypt0r 2.0 reference image...")
                image_data = urllib.request.urlopen(image_url).read()
                image = Image.open(io.BytesIO(image_data))

                # Resize image to fit window
                image.thumbnail((980, 650), Image.Resampling.LANCZOS)

                # Convert to PhotoImage
                photo = ImageTk.PhotoImage(image)

                # Create label to display image
                label = tk.Label(image_window, image=photo, bg="black")
                label.image = photo  # Keep a reference!
                label.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

                # Add close button
                close_btn = tk.Button(image_window, text="Close and Continue", command=image_window.destroy,
                                     bg="red", fg="white", font=("Arial", 12, "bold"), padx=20, pady=10)
                close_btn.pack(pady=10)

                print("[+] Wana Decrypt0r 2.0 image displayed. Close the window to continue.")

                # Wait for window to close
                image_window.wait_window()
                root.destroy()
            except Exception as e:
                print(f"[-] Error in show_image: {e}")

        # Run image display in a separate thread so it doesn't block
        img_thread = threading.Thread(target=show_image, daemon=True)
        img_thread.start()
        img_thread.join(timeout=15)  # Wait max 15 seconds

    except Exception as e:
        print(f"[-] Error displaying image: {e}")
        print("[!] Continuing without image display...")


def open_encrypted_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        print("\n--- FILE CONTENT START ---\n")
        print(content)
        print("\n--- FILE CONTENT END ---\n")
    except Exception as e:
        print("Error opening file:", e)


# menu for user interation
def ask_user():
    mode = input("\nWhat would you like to do?\n"
                 "1- Encrypt a message\n"
                 "2- Decrypt a message\n"
                 "3- Encrypt a file\n"
                 "4- Decrypt a file\n"
                 "5- Open a file\n"
                 "6- Exit\n"
                 "Enter a number: ")
    if mode == "1":
        msg = input("Enter message to encrypt: ")
        ciphertext = encrypt_message(msg)
    elif mode == "2":
        ciphertext_input = input("Enter message to decrypt: ")
        decrypt_message(ciphertext_input.encode())
    elif mode == "3":
        path = input("Enter path of file to encrypt: ")
        encrypt_file(path)
    elif mode == "4":
        path = input("Enter path of file to decrypt: ")
        decrypt_file(path)
    elif mode == "5":
        # Option 5: Open file
        print("\n[*] You selected: Open a file")
        print("Use the ABSOLUTE path of the file:")
        print("Example: /home/brandon/test/test.txt")
        path = input("Enter the full path of the file to open: ")
        display_ransomware_image()
        open_encrypted_file(path)
    elif mode == "6":
        print("Goodbye!")
        exit()
    else:
        print("Invalid selection...")
#display_ransomware_image()
while True:
    ask_user()

#!/usr/bin/env python3 

from cryptography.fernet import Fernet
import os, time, math

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
    with open(File_path, "r") as f:
        content = f.read()
    content_encrypted = content[::-1]
    with open(File_path, "w") as f:
        f.write(content_encrypted)
encrypt_file("/User/VICTUS/andrel/test.txt")

def decrypt_file(File_path):
    with open(File_path, "r") as f:
        content = f.read()
    content_original = content[::-1]
    with open(File_path, "w") as f:
        f.write(content_original)
decrypt_file("/User/VICTUS/andrel/test.txt")


# menu for user interation 
def ask_user():
    mode = input("\nWhat would you like to do?\n"
                 "1- Encrypt a message\n"
                 "2- Decrypt a message\n"
                 "3- Encrypt a file\n"
                 "4- Decrypt a file\n"
                 "5- Exit\n"
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
        print("Goodbye!")
        exit()
    else:
        print("Invalid selection...")
while True:
    ask_user()
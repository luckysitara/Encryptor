import os
import base64
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.popup import Popup
from kivy.storage.jsonstore import JsonStore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend

# File to store the master key
MASTER_KEY_FILE = "master_key.json"


class EncryptionApp(App):
    def __init__(self, **kwargs):
        super(EncryptionApp, self).__init__(**kwargs)
        self.store = JsonStore(MASTER_KEY_FILE)

    def build(self):
        layout = BoxLayout(orientation='vertical', padding=10)

        # Check if the master key is already set
        if not self.store.exists('master_key'):
            self.show_master_key_setup(layout)
        else:
            self.show_main_interface(layout)

        return layout

    def show_master_key_setup(self, layout):
        layout.clear_widgets()
        layout.add_widget(Label(text="Setup Master Key", size_hint_y=0.1))
        self.master_key_input = TextInput(hint_text="Enter Master Key", password=True, multiline=False)
        layout.add_widget(self.master_key_input)
        save_button = Button(text="Save Master Key", on_press=self.save_master_key)
        layout.add_widget(save_button)

    def save_master_key(self, instance):
        master_key = self.master_key_input.text.strip()
        if master_key:
            self.store.put('master_key', key=master_key)
            self.root.clear_widgets()
            self.show_main_interface(self.root)

    def show_main_interface(self, layout):
        layout.clear_widgets()
        layout.add_widget(Label(text="Select a file or directory to encrypt/decrypt:", size_hint_y=0.1))

        self.filechooser = FileChooserIconView()
        layout.add_widget(self.filechooser)

        self.password_input = TextInput(hint_text="Enter Password", password=True, multiline=False)
        layout.add_widget(self.password_input)

        encrypt_button = Button(text="Encrypt", on_press=self.encrypt_selected)
        decrypt_button = Button(text="Decrypt", on_press=self.decrypt_selected)

        button_layout = BoxLayout(size_hint_y=0.1)
        button_layout.add_widget(encrypt_button)
        button_layout.add_widget(decrypt_button)
        layout.add_widget(button_layout)

    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_data(self, data, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext

    def decrypt_data(self, data, key):
        iv = data[:16]
        encrypted_data = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def encrypt_file(self, file_path, password):
        salt = os.urandom(16)
        key = self.derive_key(password, salt)
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = self.encrypt_data(file_data, key)
        with open(file_path + '.enc', 'wb') as file:
            file.write(base64.b64encode(salt + encrypted_data))
        os.remove(file_path)

    def decrypt_file(self, file_path, password):
        with open(file_path, 'rb') as file:
            encrypted_data = base64.b64decode(file.read())
        salt = encrypted_data[:16]
        key = self.derive_key(password, salt)
        try:
            decrypted_data = self.decrypt_data(encrypted_data[16:], key)
        except Exception:
            # Fallback to master key if decryption fails with provided password
            master_key = self.store.get('master_key')['key']
            key = self.derive_key(master_key, salt)
            decrypted_data = self.decrypt_data(encrypted_data[16:], key)
        with open(file_path[:-4], 'wb') as file:
            file.write(decrypted_data)
        os.remove(file_path)

    def encrypt_directory(self, directory_path, password):
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                self.encrypt_file(file_path, password)

    def decrypt_directory(self, directory_path, password):
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.enc'):
                    file_path = os.path.join(root, file)
                    self.decrypt_file(file_path, password)

    def encrypt_selected(self, instance):
        selected = self.filechooser.selection
        password = self.password_input.text.strip()
        if not selected or not password:
            self.show_popup("Error", "Please select a file/directory and enter a password.")
            return

        for path in selected:
            if os.path.isdir(path):
                self.encrypt_directory(path, password)
                self.show_popup("Success", f"Directory {path} encrypted successfully.")
            elif os.path.isfile(path):
                self.encrypt_file(path, password)
                self.show_popup("Success", f"File {path} encrypted successfully.")
            else:
                self.show_popup("Error", "Invalid path provided.")

    def decrypt_selected(self, instance):
        selected = self.filechooser.selection
        password = self.password_input.text.strip()
        if not selected or not password:
            self.show_popup("Error", "Please select a file/directory and enter a password.")
            return

        for path in selected:
            if os.path.isdir(path):
                self.decrypt_directory(path, password)
                self.show_popup("Success", f"Directory {path} decrypted successfully.")
            elif os.path.isfile(path) and path.endswith('.enc'):
                self.decrypt_file(path, password)
                self.show_popup("Success", f"File {path} decrypted successfully.")
            else:
                self.show_popup("Error", "Invalid path or file provided for decryption.")

    def show_popup(self, title, message):
        popup_layout = BoxLayout(orientation='vertical', padding=10)
        popup_label = Label(text=message, size_hint_y=0.8)
        popup_button = Button(text="OK", size_hint_y=0.2)
        popup_layout.add_widget(popup_label)
        popup_layout.add_widget(popup_button)
        popup = Popup(title=title, content=popup_layout, size_hint=(0.8, 0.4))
        popup_button.bind(on_press=popup.dismiss)
        popup.open()


if __name__ == "__main__":
    EncryptionApp().run()

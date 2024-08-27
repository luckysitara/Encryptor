### Encryptor
An Encryption tool using AES

Below is a sample `README.md` file for your Android encryption app built with Kivy. This README will provide users with information about the app, how to install and use it, and some technical details.



# Android Encryption Tool

This Android Encryption Tool is a Python-based mobile application that allows users to securely encrypt and decrypt files and directories using the Advanced Encryption Standard (AES). The app requires users to set a master key on the first launch, which can be used to decrypt any files encrypted by the tool in case the original password is forgotten.

## Features

- **File and Directory Encryption:** Encrypt individual files or entire directories using a user-provided password.
- **File and Directory Decryption:** Decrypt files or directories using the same password or the master key.
- **Master Key Setup:** On the first launch, users are required to set a master key, which is securely stored and can be used to decrypt any file encrypted by the tool.
- **User-Friendly Interface:** The app provides an intuitive interface with file selection, password input, and encryption/decryption controls.
- **Cross-Platform:** While primarily designed for Android, the app is written in Python and can be run on any platform that supports Kivy.

## Installation

### Prerequisites

Before building the Android APK, ensure you have the following installed on your development environment:

- **Python 3.x**
- **Kivy:** A Python library for developing multi-touch applications.
- **Buildozer:** A tool for packaging Python apps into Android APKs.

You can install the required dependencies using `pip`:

```bash
pip install kivy cryptography
pip install buildozer
```
Linux might need this 

```bash
sudo apt install python3-pip python3-dev build-essential \
libssl-dev libffi-dev python3-setuptools \
libgmp3-dev python3-venv
```
### Building the APK

1. **Initialize Buildozer:**

   Navigate to your project directory and run:

   ```bash
   buildozer init
   ```

   This command creates a `buildozer.spec` file where you can configure the app's settings.

2. **Build the APK:**

   Run the following command to build the APK:

   ```bash
   buildozer -v android debug
   ```

   The generated APK will be located in the `bin` directory.

3. **Install on Android:**

   Transfer the APK to your Android device and install it.

## Usage

1. **First Launch - Set Master Key:**

   - When the app is launched for the first time, you will be prompted to set a master key. This key will be securely stored and can be used to decrypt any file encrypted by the app.

2. **Encrypting Files/Directories:**

   - Select the file or directory you want to encrypt using the file chooser.
   - Enter a password in the provided text input.
   - Click the "Encrypt" button to start the encryption process.
   - The original file will be deleted, and the encrypted file will be saved with a `.enc` extension.

3. **Decrypting Files/Directories:**

   - Select the encrypted file or directory you want to decrypt using the file chooser.
   - Enter the original password used during encryption or the master key.
   - Click the "Decrypt" button to start the decryption process.
   - The encrypted file will be replaced with the original file.

## Technical Details

### Cryptography

- The app uses the **AES** (Advanced Encryption Standard) algorithm in **CBC** (Cipher Block Chaining) mode for encryption and decryption.
- **PBKDF2HMAC** is used for deriving the encryption key from the password.
- The master key and encryption passwords are securely handled and not stored in plain text.

### File Handling

- The app can handle both individual files and directories. If a directory is selected, all files within the directory and its subdirectories are processed recursively.

## Security Considerations

- Ensure you do not forget the master key, as it is crucial for decrypting files if the original password is forgotten.
- The app securely deletes the original file after encryption to prevent unauthorized access.
- Always keep a backup of your master key in a secure place.

## Contributing

If you want to contribute to the development of this app, feel free to fork the repository and submit a pull request. Bug reports and feature requests are also welcome.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


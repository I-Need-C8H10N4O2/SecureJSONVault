import json
import click
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from jinja2 import Template
import getpass
import os
import base64

VERIFICATION_KEY = '__verification'
VERIFICATION_VALUE = 'CORRECT'


def load_keystore(file_path):
    """
    Load the keystore from the given file path.

    :param file_path: Path to the keystore file.
    :return: Keystore dictionary or None if the file doesn't exist or is corrupted.
    """
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError:
        click.echo('Error: Keystore file is corrupted.')
        return None
    except Exception as e:
        click.echo(f'Unexpected error: {e}')
        return None


def save_keystore(file_path, keystore):
    """
    Save the keystore to the given file path.

    :param file_path: Path to the keystore file.
    :param keystore: Keystore dictionary to save.
    """
    try:
        with open(file_path, 'w') as file:
            json.dump(keystore, file, indent=4)
    except Exception as e:
        click.echo(f'Error saving keystore: {e}')


def generate_salt():
    """
    Generate a cryptographic salt.

    :return: A 16-byte salt.
    """
    return os.urandom(16)


def derive_key(master_password, salt, iterations=200000):
    """
    Derive a key from the master password and salt using PBKDF2.

    :param master_password: The master password.
    :param salt: The cryptographic salt.
    :param iterations: Number of iterations for the key derivation function.
    :return: A derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def get_password_from_user(password):
    """
    Prompt the user for a password if not provided.

    :param password: Password provided via command line option.
    :return: The password.
    """
    if password:
        return password
    return getpass.getpass('Master password: ')


def handle_decryption(cipher, encrypted_value):
    """
    Decrypt an encrypted value.

    :param cipher: Fernet cipher object.
    :param encrypted_value: Encrypted value to decrypt.
    :return: Decrypted value or None if decryption fails.
    """
    try:
        decrypted_value = cipher.decrypt(encrypted_value.encode()).decode()
        return decrypted_value
    except InvalidToken:
        click.echo('Error: Invalid password or corrupted data.')
        return None


def initialize_keystore(keystore, master_password):
    """
    Initialize a new keystore with a verification key.

    :param keystore: Keystore dictionary.
    :param master_password: The master password.
    """
    salt = generate_salt()
    cipher = Fernet(derive_key(master_password, salt))
    encrypted_value = cipher.encrypt(VERIFICATION_VALUE.encode()).decode()
    keystore[VERIFICATION_KEY] = {
        'value': encrypted_value,
        'salt': base64.urlsafe_b64encode(salt).decode()
    }


def verify_master_password(keystore, master_password):
    """
    Verify the master password against the verification key in the keystore.

    :param keystore: Keystore dictionary.
    :param master_password: The master password.
    :return: True if the master password is correct, otherwise False.
    """
    if VERIFICATION_KEY not in keystore:
        if click.confirm('Verification key not found. Initialize new keystore?', abort=True):
            initialize_keystore(keystore, master_password)
            return True
        else:
            return False

    data = keystore[VERIFICATION_KEY]
    salt = base64.urlsafe_b64decode(data['salt'])
    cipher = Fernet(derive_key(master_password, salt))
    decrypted_value = handle_decryption(cipher, data['value'])
    return decrypted_value == VERIFICATION_VALUE


def get_keystore_and_password(file_path, password):
    """
    Load the keystore and get the master password from the user if not provided.

    :param file_path: Path to the keystore file.
    :param password: Master password.
    :return: Tuple of keystore dictionary and master password.
    """
    keystore = load_keystore(file_path)
    if keystore is None:
        click.echo(f'Keystore file {file_path} does not exist.')
        return None, None

    master_password = get_password_from_user(password)
    if not verify_master_password(keystore, master_password):
        click.echo('Error: Incorrect master password.')
        return None, None

    return keystore, master_password


@click.group()
def cli():
    """Command-line interface for keystore management."""
    pass


@cli.command()
@click.option('-f', '--file', 'file_path', required=True, help='Path to the keystore file.')
@click.option('--key', 'key', required=True, help='Key to decrypt.')
@click.option('--password', 'password', help='Master password to decrypt the key.')
def decrypt(file_path, key, password):
    """
    Decrypt a value from the keystore.

    :param file_path: Path to the keystore file.
    :param key: Key to decrypt.
    :param password: Master password.
    """
    if key == VERIFICATION_KEY:
        click.echo(f'Error: {VERIFICATION_KEY} is a reserved key and cannot be accessed.')
        return

    keystore, master_password = get_keystore_and_password(file_path, password)
    if keystore is None:
        return

    if key not in keystore:
        click.echo(f'Key {key} not found in keystore.')
        return

    try:
        salt = base64.urlsafe_b64decode(keystore[key]['salt'])
    except KeyError:
        click.echo('Error: Salt is missing or corrupted.')
        return

    cipher = Fernet(derive_key(master_password, salt))
    decrypted_value = handle_decryption(cipher, keystore[key]['value'])
    if decrypted_value is not None:
        click.echo(decrypted_value)


@cli.command()
@click.option('-f', '--file', 'file_path', required=True, help='Path to the keystore file.')
@click.option('--password', 'password', help='Master password to encrypt the key.')
@click.option('--key', 'key', required=True, help='Key to encrypt.')
@click.argument('value')
def encrypt(file_path, key, value, password):
    """
    Encrypt a value and store it in the keystore.

    :param file_path: Path to the keystore file.
    :param key: Key to encrypt.
    :param value: Value to encrypt.
    :param password: Master password.
    """
    if key == VERIFICATION_KEY:
        click.echo(f'Error: {VERIFICATION_KEY} is a reserved key and cannot be used.')
        return

    keystore = load_keystore(file_path)
    
    if keystore is None:
        keystore = {}
        click.echo(f'Keystore file {file_path} does not exist. Creating a new one.')
    
    master_password = get_password_from_user(password)
    if not verify_master_password(keystore, master_password):
        click.echo('Error: Incorrect master password.')
        return
    
    if key in keystore:
        click.echo(f'Key {key} already exists in the keystore. Use update command to modify the existing key.')
        return
    
    salt = generate_salt()
    cipher = Fernet(derive_key(master_password, salt))
    encrypted_value = cipher.encrypt(value.encode()).decode()
    keystore[key] = {
        'value': encrypted_value,
        'salt': base64.urlsafe_b64encode(salt).decode()
    }
    save_keystore(file_path, keystore)
    click.echo(f'Encrypted and saved {key}.')


@cli.command()
@click.option('-f', '--file', 'file_path', required=True, help='Path to the keystore file.')
@click.option('--key', 'key', required=True, help='Key to remove.')
@click.option('--password', 'password', help='Master password.')
def remove(file_path, key, password):
    """
    Remove a key from the keystore.

    :param file_path: Path to the keystore file.
    :param key: Key to remove.
    :param password: Master password.
    """
    if key == VERIFICATION_KEY:
        click.echo(f'Error: {VERIFICATION_KEY} is a reserved key and cannot be removed.')
        return

    keystore, master_password = get_keystore_and_password(file_path, password)
    if keystore is None:
        return

    if key in keystore:
        del keystore[key]
        save_keystore(file_path, keystore)
        click.echo(f'Removed {key}.')
    else:
        click.echo(f'Key {key} not found.')


@cli.command()
@click.option('-f', '--file', 'file_path', required=True, help='Path to the keystore file.')
@click.option('--template', 'template_path', required=True, help='Path to the Jinja2 template file.')
@click.option('--output', 'output_path', required=False, help='Path to save the rendered template.')
@click.option('--password', 'password', help='Master password to decrypt the keys.')
def render(file_path, template_path, output_path, password):
    """
    Render a Jinja2 template using decrypted keys from the keystore.

    :param file_path: Path to the keystore file.
    :param template_path: Path to the Jinja2 template file.
    :param output_path: Path to save the rendered template.
    :param password: Master password.
    """
    keystore, master_password = get_keystore_and_password(file_path, password)
    if keystore is None:
        return

    decrypted_keys = {}
    for key, data in keystore.items():
        if key == VERIFICATION_KEY:
            continue
        try:
            salt = base64.urlsafe_b64decode(data['salt'])
        except KeyError:
            click.echo(f'Error: Salt for key {key} is missing or corrupted.')
            return
        
        cipher = Fernet(derive_key(master_password, salt))
        decrypted_value = handle_decryption(cipher, data['value'])
        if decrypted_value is not None:
            decrypted_keys[key] = decrypted_value

    try:
        with open(template_path, 'r') as file:
            template_content = file.read()
            
        template = Template(template_content)
        rendered_content = template.render(decrypted_keys)
        
        with open(output_path or template_path, 'w') as file:
            file.write(rendered_content)
        
        click.echo(f'Template {template_path} has been rendered and saved to {output_path or template_path}.')
    except FileNotFoundError:
        click.echo(f'Error: Template file {template_path} does not exist.')
    except Exception as e:
        click.echo(f'Error rendering template: {e}')


@cli.command()
@click.option('-f', '--file', 'file_path', required=True, help='Path to the keystore file.')
@click.option('--password', 'password', help='Master password to encrypt the key.')
@click.option('--key', 'key', required=True, help='Key to update.')
@click.argument('value')
def update(file_path, key, value, password):
    """
    Update an existing key in the keystore.

    :param file_path: Path to the keystore file.
    :param key: Key to update.
    :param value: New value to encrypt and store.
    :param password: Master password.
    """
    if key == VERIFICATION_KEY:
        click.echo(f'Error: {VERIFICATION_KEY} is a reserved key and cannot be updated.')
        return

    keystore, master_password = get_keystore_and_password(file_path, password)
    if keystore is None:
        return
    
    if key not in keystore:
        click.echo(f'Key {key} does not exist in the keystore. Use encrypt command to add a new key.')
        return
    
    salt = generate_salt()
    cipher = Fernet(derive_key(master_password, salt))
    encrypted_value = cipher.encrypt(value.encode()).decode()
    keystore[key] = {
        'value': encrypted_value,
        'salt': base64.urlsafe_b64encode(salt).decode()
    }
    save_keystore(file_path, keystore)
    click.echo(f'Updated and saved {key}.')


if __name__ == '__main__':
    cli()

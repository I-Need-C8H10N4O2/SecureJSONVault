# SecureJSONVault 🛡️

SecureJSONVault is a simple Python command-line script designed to securely manage secrets in a JSON keystore file. It allows encryption and decryption of secrets using a master password, ensuring that sensitive information can be safely stored and accessed. The script integrates with Jinja2 templating to dynamically render configuration files with encrypted secrets.

# 🚀 Why SecureJSONVault?

SecureJSONVault was developed to address the challenge of securely storing and accessing sensitive information such as passwords, API keys, and other secrets during build and deployment processes. I have written the script to address the following challenges:
- **Large Number of Keys:** Managing many secrets can be quite cumbersome using built-in secret functionality in CI/CD platforms.
- **Lack of Advanced Tools:** In many projects, I do not have access to advanced tools like AWS Credential Manager or HashiCorp Vault. SecureJSONVault offers a very simple, easy-to-set-up alternative.
- **Simplicity and Quick Setup:** Unlike more complex solutions, SecureJSONVault is designed to be a quick script that can be easily integrated into your workflow without the overhead of setting up additional infrastructure.

As a DevOps engineer, I often struggle to store secrets securely, especially when dealing with a large number of keys. It is not feasible to keep defining Jenkins secrets or GitHub Actions secrets for each key due to management and traceability challenges. SecureJSONVault allows storing the keystore file along with the script in the repository, with only one master password to manage. Previously, I used Ansible Vault, but it wasn't always suitable as setting up Ansible and writing playbooks added unnecessary complexity. It goes without saying, this script may not suit your use-case and is *not* a replacement for more advanced solutions like AWS Credential Manager or HashiCorp Vault, but it is a simple and quick alternative for small projects or personal use.

## 🌟 Features

- 🔐 Securely encrypt and decrypt secrets with a master password.
- 📁 Store secrets in a JSON keystore file.
- 📝 Render a Jinja2 template from variables in keystore.

## 📦 Installation 

It is only one script, so you can simply download it and use it. Of course, you need to have Python installed on your system along with the dependencies in the `requirements.txt` file. You can install the dependencies using the following command:

```bash
pip install -r requirements.txt
```
Alternatively, you can install the script with pip using the following command:

```bash
pip install securejsonvault
```

## 📖 Usage

### Encrypt a Secret

```bash
sjv -f keystore.json encrypt --key my_secret "secret_value" --password "master_password"
```

### Decrypt a Secret

```bash
sjv -f keystore.json decrypt --key my_secret --password "master_password"
```

### Remove a Secret

```bash
sjv -f keystore.json remove --key my_secret --password "master_password"
```

### Render a Jinja2 Template

```bash
sjv -f keystore.json render --template config_template.j2 --password "master_password"
```

### Update a Secret

```bash
sjv -f keystore.json update --key my_secret "new_secret_value" --password "master_password"
```

## ⚠️ Disclaimer

SecureJSONVault is provided "as-is" without any warranties. Use it at your own risk. The author is not responsible for any issues or liabilities that arise from using this tool.

## 🤝 Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss any changes.

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

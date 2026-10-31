![Banner](banner.png)

# misconfig-ConfigObfuscator
Redacts sensitive data (e.g., passwords, API keys) in configuration files, replacing them with placeholders. A value is redacted whenever its key name matches the sensitive name set (password, passwd, pwd, passphrase, api_key, apikey, access_key, private_key, secret, client_secret, token, auth_token, credentials, credential, signing_key, session_key, including names that contain one of those as a part, such as numeric_password), whatever the value type, at the top level or nested. Helps with sharing configurations securely for debugging or auditing. After a run the tool reports how many values it redacted and for which keys; values themselves are never printed. - Focused on Check for misconfigurations in configuration files or infrastructure definitions

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-configobfuscator`

## Usage
`python3 main.py config.yaml [-o output.yaml] [-p <REDACTED>] [-d]`

## Parameters
- `input_file`: Path to the input configuration file (positional, required).
- `-h`: Show help message and exit
- `-o`: Path to the output file. If not specified, overwrites the input file. The output format follows the output extension (.yaml, .yml, or .json); naming a different extension than the input converts the format, and an unknown extension is refused at exit 1 before anything is written.
- `-p`: Placeholder string to replace sensitive data with (default: <REDACTED>).
- `-d`: Enable debug logging.

An empty configuration writes an empty output with a plain line saying nothing was present to redact. A configuration whose top level is not a mapping is refused at exit 1 with no output written.

## License
Copyright (c) ShadowStrikeHQ

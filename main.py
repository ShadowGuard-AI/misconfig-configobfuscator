#!/usr/bin/env python3

import argparse
import re
import os
import logging
import yaml
import json
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ConfigObfuscator:
    """
    Redacts sensitive data (e.g., passwords, API keys) in configuration files.
    """

    def __init__(self, input_file: str, output_file: Optional[str] = None, placeholder: str = "<REDACTED>"):
        """
        Initializes the ConfigObfuscator.

        Args:
            input_file (str): The path to the input configuration file.
            output_file (Optional[str]): The path to the output file. If None, overwrites the input file.
            placeholder (str): The string to replace sensitive data with.
        """
        self.input_file = input_file
        self.output_file = output_file if output_file else input_file
        self.placeholder = placeholder
        # Sensitive key name stems. A key matches when a stem is the whole
        # normalized key, or a whole underscore separated part of it, or the
        # key starts or ends with the stem (api_key, client_secret,
        # numeric_password, private_key, passwd, and so on).
        self.sensitive_stems = [
            "password", "passwd", "pwd", "passphrase",
            "api_key", "apikey", "access_key", "private_key",
            "secret", "client_secret", "token", "auth_token",
            "credentials", "credential", "signing_key", "session_key",
        ]
        self.redacted_keys = []
        # Patterns for strings that embed a "name: value" pair (for example
        # items inside a list). The value part is what gets replaced.
        self.patterns = [
            r"((?:%s)\s*:).*" % stem for stem in self.sensitive_stems
        ] + [
            r'(("(?:%s)"\s*:).*)' % stem for stem in self.sensitive_stems
        ]

    def is_sensitive_key(self, key) -> bool:
        """Return True when a mapping key name is a sensitive name."""
        normalized = str(key).strip().lower().replace("-", "_").replace(" ", "_").strip('"').strip("'")
        padded = f"_{normalized}_"
        for stem in self.sensitive_stems:
            if stem == normalized or f"_{stem}_" in padded or normalized.startswith(stem + "_") or normalized.endswith("_" + stem):
                return True
        return False

    def load_config(self) -> Optional[Dict[str, Any]]:
        """
        Loads the configuration file.  Supports YAML and JSON.

        Returns:
            Optional[Dict[str, Any]]: The configuration as a dictionary, or None if loading fails.
        """
        try:
            with open(self.input_file, 'r') as f:
                file_content = f.read()

            if not file_content.strip():
                return {}

            if self.input_file.endswith('.json'):
                try:
                    config = json.loads(file_content)
                    logging.info(f"Successfully loaded {self.input_file} as JSON.")
                    return config
                except json.JSONDecodeError:
                    logging.error(f"Failed to load {self.input_file} as JSON.")
                    return None

            # Attempt to parse as YAML first
            try:
                config = yaml.safe_load(file_content)
                logging.info(f"Successfully loaded {self.input_file} as YAML.")
                return config
            except yaml.YAMLError:
                logging.debug(f"{self.input_file} is not valid YAML.  Attempting JSON parsing.")
                pass  # Try JSON instead

            # Attempt to parse as JSON
            try:
                config = json.loads(file_content)
                logging.info(f"Successfully loaded {self.input_file} as JSON.")
                return config
            except json.JSONDecodeError:
                logging.error(f"Failed to load {self.input_file} as either YAML or JSON.")
                return None

        except FileNotFoundError:
            logging.error(f"File not found: {self.input_file}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading {self.input_file}: {e}")
            return None

    def obfuscate_config(self, config: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        """
        Obfuscates sensitive data in the configuration dictionary.

        A value is replaced with the placeholder whenever its key name
        matches the sensitive name set, whatever the value type (string,
        number, boolean, mapping, or list). Nested mappings are walked
        recursively. String values and list items that embed a
        "name: value" pair for a sensitive name are also redacted.
        Redacted keys are recorded by dotted path in self.redacted_keys;
        values themselves are never recorded.
        """

        def obfuscate_value(value: Any, path: str) -> Any:
            """Recursively obfuscates values within nested structures."""
            if isinstance(value, str):
                for pattern in self.patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        self.redacted_keys.append(path)
                        return self.placeholder
                return value
            elif isinstance(value, dict):
                return self.obfuscate_config(value, path)
            elif isinstance(value, list):
                return [obfuscate_value(item, path) for item in value]
            else:
                return value

        for key, value in config.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if self.is_sensitive_key(key):
                config[key] = self.placeholder
                self.redacted_keys.append(path)
            elif isinstance(value, dict):
                config[key] = self.obfuscate_config(value, path)
            elif isinstance(value, list):
                config[key] = [obfuscate_value(item, path) for item in value]
            elif isinstance(value, str):
                config[key] = obfuscate_value(value, path)

        return config

    def save_config(self, config: Dict[str, Any]) -> bool:
        """
        Saves the obfuscated configuration to the output file.

        Args:
            config (Dict[str, Any]): The obfuscated configuration dictionary.

        Returns:
            bool: True if the configuration was saved successfully, False otherwise.
        """
        # The output format follows the output extension. Without an
        # extension naming a different format, the output file is the input
        # file or shares its extension, so the input format is preserved.
        # Unknown extensions are refused before the file is opened.
        if self.output_file.endswith(('.yaml', '.yml')):
            output_format = 'YAML'
        elif self.output_file.endswith('.json'):
            output_format = 'JSON'
        else:
            logging.error(f"Unknown file extension for {self.output_file}. Refusing to write: use a .yaml, .yml, or .json output file.")
            return False
        input_format = 'JSON' if self.input_file.endswith('.json') else 'YAML'
        if output_format != input_format:
            logging.info(f"Converting from {input_format} to {output_format}, as named by the output file extension.")
        try:
            if output_format == 'YAML':
                with open(self.output_file, 'w') as f:
                    yaml.dump(config, f, indent=2)  # Use indent for readability
                logging.info(f"Successfully saved obfuscated config to {self.output_file} as YAML.")
                return True
            else:
                with open(self.output_file, 'w') as f:
                    json.dump(config, f, indent=2)  # Use indent for readability
                logging.info(f"Successfully saved obfuscated config to {self.output_file} as JSON.")
                return True
        except Exception as e:
            logging.error(f"Failed to save configuration to {self.output_file}: {e}")
            return False

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Redacts sensitive data in configuration files.")
    parser.add_argument("input_file", help="Path to the input configuration file.")
    parser.add_argument("-o", "--output_file", help="Path to the output file.  If not specified, overwrites the input file.")
    parser.add_argument("-p", "--placeholder", default="<REDACTED>", help="Placeholder string to replace sensitive data with (default: <REDACTED>).")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug logging.")
    return parser

def main():
    """
    Main function to execute the configuration obfuscation.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)  # Set logging level to DEBUG

    logging.debug(f"Input file: {args.input_file}")
    logging.debug(f"Output file: {args.output_file}")
    logging.debug(f"Placeholder: {args.placeholder}")

    # Input Validation
    if not os.path.exists(args.input_file):
        logging.error(f"Error: Input file '{args.input_file}' does not exist.")
        return 1

    obfuscator = ConfigObfuscator(args.input_file, args.output_file, args.placeholder)
    config = obfuscator.load_config()

    if config is None:
        logging.error(f"Could not load a configuration from '{args.input_file}'. No output written.")
        return 1

    if not isinstance(config, dict):
        logging.error(f"Configuration in '{args.input_file}' is not a mapping at the top level (got {type(config).__name__}). No output written.")
        return 1

    if not config:
        # An empty mapping: write the empty output and say plainly that
        # there was nothing present to redact.
        if obfuscator.save_config(config):
            print("Configuration was empty: nothing was present to redact.")
            return 0
        return 1

    obfuscated_config = obfuscator.obfuscate_config(config)
    if obfuscator.save_config(obfuscated_config):
        redacted = obfuscator.redacted_keys
        print(f"Redacted {len(redacted)} sensitive value(s) for keys: {', '.join(redacted) if redacted else 'none'}")
        logging.info("Configuration obfuscation completed successfully.")
        return 0
    else:
        return 1


if __name__ == "__main__":
    # Usage Example
    # ./main.py config.yaml -o config_obfuscated.yaml -p "******"
    # ./main.py config.json
    exit(main())
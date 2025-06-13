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
        self.patterns = [
            r"(password\s*:).*",  # Matches password: anything
            r"(api_key\s*:).*",   # Matches api_key: anything
            r"(secret\s*:).*",    # Matches secret: anything
            r"(token\s*:).*",     # Matches token: anything
            r"(access_key\s*:).*", # Matches access_key: anything
            r"(credentials\s*:).*", # Matches credentials: anything
            r"(\"password\"\s*:).*",
            r"(\"api_key\"\s*:).*",
            r"(\"secret\"\s*:).*",
            r"(\"token\"\s*:).*",
            r"(\"access_key\"\s*:).*",
            r"(\"credentials\"\s*:).*",
        ]

    def load_config(self) -> Optional[Dict[str, Any]]:
        """
        Loads the configuration file.  Supports YAML and JSON.

        Returns:
            Optional[Dict[str, Any]]: The configuration as a dictionary, or None if loading fails.
        """
        try:
            with open(self.input_file, 'r') as f:
                file_content = f.read()

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

    def obfuscate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Obfuscates sensitive data in the configuration dictionary.

        Args:
            config (Dict[str, Any]): The configuration dictionary.

        Returns:
            Dict[str, Any]: The obfuscated configuration dictionary.
        """

        def obfuscate_value(value: Any) -> Any:
            """Recursively obfuscates values within nested structures."""
            if isinstance(value, str):
                # Apply regex obfuscation if it's a string
                for pattern in self.patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return self.placeholder
                return value
            elif isinstance(value, dict):
                return self.obfuscate_config(value)  # Recursive call for dictionaries
            elif isinstance(value, list):
                return [obfuscate_value(item) for item in value]  # Recursive call for lists
            else:
                return value  # Return non-string values unchanged


        for key, value in config.items():
            if isinstance(value, str):
                # Apply regex obfuscation to string values
                for pattern in self.patterns:
                    if re.search(pattern, key, re.IGNORECASE): # Check key too
                        config[key] = self.placeholder
                        break # Only match the first pattern
            elif isinstance(value, dict):
                config[key] = self.obfuscate_config(value)  # Recursive call for dictionaries
            elif isinstance(value, list):
                config[key] = [obfuscate_value(item) for item in value] # Recursive call for lists

        return config

    def save_config(self, config: Dict[str, Any]) -> bool:
        """
        Saves the obfuscated configuration to the output file.

        Args:
            config (Dict[str, Any]): The obfuscated configuration dictionary.

        Returns:
            bool: True if the configuration was saved successfully, False otherwise.
        """
        try:
            # Determine file type based on extension
            if self.output_file.endswith(('.yaml', '.yml')):
                with open(self.output_file, 'w') as f:
                    yaml.dump(config, f, indent=2)  # Use indent for readability
                logging.info(f"Successfully saved obfuscated config to {self.output_file} as YAML.")
                return True
            elif self.output_file.endswith('.json'):
                with open(self.output_file, 'w') as f:
                    json.dump(config, f, indent=2)  # Use indent for readability
                logging.info(f"Successfully saved obfuscated config to {self.output_file} as JSON.")
                return True
            else:
                logging.warning(f"Unknown file extension for {self.output_file}. Attempting to save as YAML.")
                with open(self.output_file, 'w') as f:
                    yaml.dump(config, f, indent=2)
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

    if config:
        obfuscated_config = obfuscator.obfuscate_config(config)
        if obfuscator.save_config(obfuscated_config):
            logging.info("Configuration obfuscation completed successfully.")
            return 0
        else:
            return 1
    else:
        return 1


if __name__ == "__main__":
    # Usage Example
    # ./main.py config.yaml -o config_obfuscated.yaml -p "******"
    # ./main.py config.json
    exit(main())
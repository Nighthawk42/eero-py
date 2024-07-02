# eero-py
 eero-py is a Python-based CLI tool designed to interact with the eero API. This tool allows users to dump information about their eero networks through a simple command-line.

## Features

- Log into your eero account, using either your e-mail or phone number.
- 2FA support.
- Securely stores your session information.
- Dump and monitor your eero network

## Installation

To get started, clone the repository and install the required dependencies:

```
git clone https://github.com/yourusername/eero-py.git
cd eero-py
pip install -r requirements.txt
```

## Usage

- **Account Information**
```
python eero_cli.py account
```
Retrieves and displays your account information.

- **List Devices:**
```
python eero_cli.py devices
```
Lists all devices connected to your eero network.

- **Get Network Status:**
```
python eero_cli.py networks 
```
Displays the current status of your eero network.

- **Display Session Token**
```
python eero_cli.py session
```
Displays the encrypted session token if it exists.

## Output
```
python eero_cli.py devices --output devices.json
```
You can save the output of a query by appending the --output switch after the command. JSON and CSV are supported.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for review.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

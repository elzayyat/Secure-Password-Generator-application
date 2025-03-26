# Secure Password Generator

A Python application that generates secure, random passwords with customizable parameters.

## Features

- Generate strong, random passwords with user-defined length
- Customize password content with options for:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Digits (0-9)
  - Special characters (!@#$%^&*)
- Simple and intuitive graphical user interface
- Copy generated passwords to clipboard with one click

## Requirements

- Python 3.6 or higher
- Required packages:
  - tkinter (included in standard Python installation)
  - pyperclip

## Installation

1. Clone or download this repository
2. Install the required packages:

```
pip install pyperclip
```

## Usage

Run the application with:

```
python password_generator.py
```

### How to use:

1. Adjust the password length using the slider (4-50 characters)
2. Select which character types to include in your password
3. Click "Generate Password" to create a new password
4. Use "Copy to Clipboard" to copy the password for use elsewhere

## Implementation Details

The application ensures that generated passwords include at least one character from each selected character type (uppercase, lowercase, digits, special characters) when those options are enabled. This guarantees that passwords meet common security requirements for different character types.

The password generation algorithm:
1. Creates a pool of allowed characters based on user selections
2. Ensures at least one character from each selected type is included
3. Fills the remaining length with random characters from the pool
4. Shuffles all characters to ensure randomness

## Security Considerations

This tool uses Python's `random` module, which is suitable for most general purposes but not for cryptographic applications. For highly sensitive security applications, consider using `secrets` module instead.
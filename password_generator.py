import random
import string
import pyperclip
import tkinter as tk
from tkinter import ttk, messagebox

class PasswordGenerator:
    def __init__(self):
        self.uppercase_chars = string.ascii_uppercase
        self.lowercase_chars = string.ascii_lowercase
        self.digit_chars = string.digits
        self.special_chars = string.punctuation
        
    def generate_password(self, length, use_uppercase=True, use_lowercase=True, 
                         use_digits=True, use_special_chars=True):
        # Validate inputs
        if length < 4 and (use_uppercase and use_lowercase and use_digits and use_special_chars):
            raise ValueError("Password length must be at least 4 to include all character types")
        
        if not any([use_uppercase, use_lowercase, use_digits, use_special_chars]):
            raise ValueError("At least one character type must be selected")
        
        # Create character pool based on selected options
        char_pool = ""
        required_chars = []
        
        if use_uppercase:
            char_pool += self.uppercase_chars
            required_chars.append(random.choice(self.uppercase_chars))
            
        if use_lowercase:
            char_pool += self.lowercase_chars
            required_chars.append(random.choice(self.lowercase_chars))
            
        if use_digits:
            char_pool += self.digit_chars
            required_chars.append(random.choice(self.digit_chars))
            
        if use_special_chars:
            char_pool += self.special_chars
            required_chars.append(random.choice(self.special_chars))
        
        # Generate password with required characters
        remaining_length = length - len(required_chars)
        
        if remaining_length < 0:
            raise ValueError(f"Password length too short to include all required character types. Minimum length needed: {len(required_chars)}")
        
        # Generate the remaining characters randomly
        password_chars = required_chars + [random.choice(char_pool) for _ in range(remaining_length)]
        
        # Shuffle the password characters to ensure randomness
        random.shuffle(password_chars)
        
        # Convert list of characters to string
        password = ''.join(password_chars)
        
        return password

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Generator")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        # Set theme colors
        self.bg_color = "#f0f0f0"
        self.accent_color = "#4a6ea9"
        self.root.configure(bg=self.bg_color)
        
        self.password_generator = PasswordGenerator()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_label = tk.Label(
            self.root, 
            text="Secure Password Generator", 
            font=("Helvetica", 16, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack(pady=20)
        
        # Main frame
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Password length
        length_frame = tk.Frame(main_frame, bg=self.bg_color)
        length_frame.pack(fill="x", pady=5)
        
        length_label = tk.Label(
            length_frame, 
            text="Password Length:", 
            bg=self.bg_color,
            font=("Helvetica", 10)
        )
        length_label.pack(side="left")
        
        self.length_var = tk.IntVar(value=12)
        length_scale = ttk.Scale(
            length_frame, 
            from_=4, 
            to=50, 
            orient="horizontal", 
            variable=self.length_var,
            command=self.update_length_label
        )
        length_scale.pack(side="left", fill="x", expand=True, padx=10)
        
        self.length_value_label = tk.Label(
            length_frame, 
            text="12", 
            width=3,
            bg=self.bg_color
        )
        self.length_value_label.pack(side="left")
        
        # Character types frame
        char_types_frame = tk.LabelFrame(
            main_frame, 
            text="Character Types", 
            bg=self.bg_color,
            font=("Helvetica", 10)
        )
        char_types_frame.pack(fill="x", pady=10)
        
        # Character type checkboxes
        self.uppercase_var = tk.BooleanVar(value=True)
        uppercase_check = ttk.Checkbutton(
            char_types_frame, 
            text="Uppercase Letters (A-Z)", 
            variable=self.uppercase_var
        )
        uppercase_check.grid(row=0, column=0, sticky="w", padx=20, pady=5)
        
        self.lowercase_var = tk.BooleanVar(value=True)
        lowercase_check = ttk.Checkbutton(
            char_types_frame, 
            text="Lowercase Letters (a-z)", 
            variable=self.lowercase_var
        )
        lowercase_check.grid(row=1, column=0, sticky="w", padx=20, pady=5)
        
        self.digits_var = tk.BooleanVar(value=True)
        digits_check = ttk.Checkbutton(
            char_types_frame, 
            text="Digits (0-9)", 
            variable=self.digits_var
        )
        digits_check.grid(row=0, column=1, sticky="w", padx=20, pady=5)
        
        self.special_var = tk.BooleanVar(value=True)
        special_check = ttk.Checkbutton(
            char_types_frame, 
            text="Special Characters (!@#$%)", 
            variable=self.special_var
        )
        special_check.grid(row=1, column=1, sticky="w", padx=20, pady=5)
        
        # Generated password frame
        password_frame = tk.Frame(main_frame, bg=self.bg_color)
        password_frame.pack(fill="x", pady=10)
        
        password_label = tk.Label(
            password_frame, 
            text="Generated Password:", 
            bg=self.bg_color,
            font=("Helvetica", 10)
        )
        password_label.pack(anchor="w")
        
        # Password display
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_frame, 
            textvariable=self.password_var, 
            font=("Courier", 12),
            width=40
        )
        password_entry.pack(fill="x", pady=5)
        
        # Buttons frame
        buttons_frame = tk.Frame(main_frame, bg=self.bg_color)
        buttons_frame.pack(fill="x", pady=10)
        
        generate_button = ttk.Button(
            buttons_frame, 
            text="Generate Password", 
            command=self.generate_password
        )
        generate_button.pack(side="left", padx=5)
        
        copy_button = ttk.Button(
            buttons_frame, 
            text="Copy to Clipboard", 
            command=self.copy_to_clipboard
        )
        copy_button.pack(side="left", padx=5)
        
    def update_length_label(self, event=None):
        self.length_value_label.config(text=str(self.length_var.get()))
        
    def generate_password(self):
        try:
            password = self.password_generator.generate_password(
                length=self.length_var.get(),
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_digits=self.digits_var.get(),
                use_special_chars=self.special_var.get()
            )
            self.password_var.set(password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))
    
    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password to copy!")

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
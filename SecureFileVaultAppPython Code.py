import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import base64
import os
from cryptography.fernet import Fernet
import shutil


class SecureFileVaultApp:
    def __init__(self, root):  # Correct constructor
        self.root = root
        self.root.title("Secure File Vault")
        self.root.geometry("800x600")
        self.root.configure(bg="#2E3440")

        # Set colors and fonts
        self.primary_color = "#4C566A"
        self.secondary_color = "#D8DEE9"
        self.accent_color = "#5E81AC"
        self.dialog_bg = "#ECEFF4"
        self.dialog_fg = "#2E3440"
        self.font = ("Helvetica", 12)

        # To store user inputs and results
        self.backup_option = tk.BooleanVar(value=True)

        # Initialize the app
        self.show_main_screen()

    def show_main_screen(self):
        """Display the main screen."""
        for widget in self.root.winfo_children():
            widget.destroy()

        # Title Section
        title_frame = tk.Frame(self.root, bg=self.primary_color, pady=20)
        title_frame.pack(fill=tk.X)
        tk.Label(
            title_frame,
            text="Secure File Vault",
            font=("Helvetica", 18, "bold"),
            bg=self.primary_color,
            fg=self.secondary_color,
        ).pack()

        # Main Options Section
        options_frame = tk.Frame(self.root, bg="#3B4252", pady=30)
        options_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=10)

        tk.Label(
            options_frame,
            text="Choose an Option",
            font=("Helvetica", 14),
            bg="#3B4252",
            fg=self.secondary_color,
        ).pack(pady=20)

        ttk.Button(
            options_frame,
            text="Text Encryption/Decryption",
            command=self.show_text_screen,
            style="Custom.TButton",
            width=30
        ).pack(pady=10)

        ttk.Button(
            options_frame,
            text="File Encryption/Decryption",
            command=self.show_file_screen,
            style="Custom.TButton",
            width=30
        ).pack(pady=10)

        # Footer Section
        footer_frame = tk.Frame(self.root, bg=self.primary_color, pady=10)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(
            footer_frame,
            text="© 2024 Secure File Vault",
            font=("Helvetica", 10),
            bg=self.primary_color,
            fg=self.secondary_color,
        ).pack()

    def show_text_screen(self):
        """Display the text encryption/decryption screen."""
        for widget in self.root.winfo_children():
            widget.destroy()

        self.create_back_button()
        self.create_title("Text Encryption/Decryption")

        # Input fields
        tk.Label(self.root, text="Enter Text:", font=self.font, fg=self.secondary_color, bg="#2E3440").pack(pady=10)
        self.text_entry = ttk.Entry(self.root, width=50)
        self.text_entry.pack(pady=10)

        tk.Label(self.root, text="Enter Password:", font=self.font, fg=self.secondary_color, bg="#2E3440").pack(pady=10)
        self.password_entry_text = ttk.Entry(self.root, show="*", width=30)
        self.password_entry_text.pack(pady=10)

        # Buttons
        self.create_button("Encrypt Text", self.encrypt_text)
        self.create_button("Decrypt Text", self.decrypt_text)

        # Save Buttons
        self.create_button("Save Original Text", self.save_original_text)
        self.create_button("Save Encrypted Text", self.save_encrypted_text)
        self.create_button("Save Decrypted Text", self.save_decrypted_text)

        # Dialog Area
        self.dialog_label = tk.Label(
            self.root,
            text="Results will be displayed here.",
            font=self.font,
            fg=self.dialog_fg,
            bg=self.dialog_bg,
            wraplength=600,
            justify="left",
            relief="groove",
            padx=10,
            pady=10
        )
        self.dialog_label.pack(pady=20)

    def show_file_screen(self):
        """Display the file encryption/decryption screen."""
        for widget in self.root.winfo_children():
            widget.destroy()

        self.create_back_button()
        self.create_title("File Encryption/Decryption")

        # Enable Backup
        tk.Checkbutton(
            self.root,
            text="Enable Backup",
            variable=self.backup_option,
            bg="#2E3440",
            fg=self.secondary_color,
            selectcolor="#2E3440",
            font=self.font
        ).pack(pady=10)

        # Password Entry
        tk.Label(self.root, text="Enter Password:", font=self.font, fg=self.secondary_color, bg="#2E3440").pack(pady=10)
        self.file_password_entry = ttk.Entry(self.root, show="*", width=30)
        self.file_password_entry.pack(pady=10)

        # Buttons for file encryption/decryption
        self.create_button("Encrypt File", self.encrypt_file)
        self.create_button("Decrypt File", self.decrypt_file)

        # Dialog Area
        self.dialog_label = tk.Label(
            self.root,
            text="Results will be displayed here.",
            font=self.font,
            fg=self.dialog_fg,
            bg=self.dialog_bg,
            wraplength=600,
            justify="left",
            relief="groove",
            padx=10,
            pady=10
        )
        self.dialog_label.pack(pady=20)

    def create_back_button(self):
        """Create a back button."""
        ttk.Button(self.root, text="Back", command=self.show_main_screen, style="Custom.TButton").pack(pady=10, anchor="w", padx=10)

    def create_title(self, text):
        """Create a title for screens."""
        tk.Label(self.root, text=text, font=("Helvetica", 16, "bold"), fg=self.secondary_color, bg="#2E3440").pack(pady=10)

    def create_button(self, text, command):
        """Create a styled button."""
        ttk.Button(self.root, text=text, command=command, style="Custom.TButton").pack(pady=10)

    def encrypt_text(self):
        """Encrypt text entered by the user."""
        password = self.password_entry_text.get()
        text = self.text_entry.get()

        if text and password:
            hashed_password = hashlib.sha256(password.encode()).digest()
            fernet = Fernet(base64.urlsafe_b64encode(hashed_password[:32]))
            self.encrypted_text = fernet.encrypt(text.encode()).decode()

            self.update_dialog(f"Encrypted Text:\n{self.encrypted_text}")
            messagebox.showinfo("Success", "Text Encrypted Successfully!")

    def decrypt_text(self):
        """Decrypt the encrypted text."""
        password = self.password_entry_text.get()
        encrypted_text = self.dialog_label.cget("text").replace("Encrypted Text:\n", "")

        if encrypted_text and password:
            hashed_password = hashlib.sha256(password.encode()).digest()
            fernet = Fernet(base64.urlsafe_b64encode(hashed_password[:32]))

            try:
                self.decrypted_text = fernet.decrypt(encrypted_text.encode()).decode()
                self.update_dialog(f"Decrypted Text:\n{self.decrypted_text}")
                messagebox.showinfo("Success", "Text Decrypted Successfully!")
            except Exception:
                self.update_dialog("Error: Failed to decrypt text!")
                messagebox.showerror("Error", "Failed to decrypt text!")

    def save_original_text(self):
        """Save original text to a file."""
        text = self.text_entry.get()
        if text:
            self.save_to_file(text, "Original Text")

    def save_encrypted_text(self):
        """Save encrypted text to a file."""
        if hasattr(self, 'encrypted_text') and self.encrypted_text:
            self.save_to_file(self.encrypted_text, "Encrypted Text")

    def save_decrypted_text(self):
        """Save decrypted text to a file."""
        if hasattr(self, 'decrypted_text') and self.decrypted_text:
            self.save_to_file(self.decrypted_text, "Decrypted Text")

    def save_to_file(self, content, title):
        """Save content to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(content)
            messagebox.showinfo("Success", f"{title} saved to {file_path}")

    def encrypt_file(self):
        """Encrypt a file."""
        password = self.file_password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        file_path = filedialog.askopenfilename(title="Select File to Encrypt", filetypes=[("All Files", ".")])

        if not file_path:
            messagebox.showwarning("Warning", "Please select a file to encrypt.")
            return

        try:
            # Generate key from password
            hashed_password = hashlib.sha256(password.encode()).digest()
            fernet = Fernet(base64.urlsafe_b64encode(hashed_password[:32]))

            # Read the file data to encrypt
            with open(file_path, "rb") as file:
                file_data = file.read()

            # Encrypt the file data
            encrypted_data = fernet.encrypt(file_data)

            # Backup Option: Create a backup before overwriting
            if self.backup_option.get():
                backup_path = file_path + ".backup"
                shutil.copy(file_path, backup_path)
                self.update_dialog(f"Backup created at {backup_path}")

            # Save encrypted file with a new name (e.g., .enc extension)
            encrypted_file_path = file_path + ".enc"
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)

            self.update_dialog(f"Encrypted file saved to {encrypted_file_path}")
            messagebox.showinfo("Success", "File Encrypted Successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt the file: {e}")

    def decrypt_file(self):
        """Decrypt an encrypted file."""
        password = self.file_password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        file_path = filedialog.askopenfilename(title="Select Encrypted File to Decrypt", filetypes=[("Encrypted files", "*.enc")])

        if not file_path:
            messagebox.showwarning("Warning", "Please select an encrypted file to decrypt.")
            return

        try:
            # Generate key from password
            hashed_password = hashlib.sha256(password.encode()).digest()
            fernet = Fernet(base64.urlsafe_b64encode(hashed_password[:32]))

            # Read the encrypted file data
            with open(file_path, "rb") as file:
                encrypted_data = file.read()

            # Decrypt the file data
            decrypted_data = fernet.decrypt(encrypted_data)

            # Save decrypted file with a new name
            decrypted_file_path = file_path.rsplit(".enc", 1)[0]  # Remove .enc extension
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)

            self.update_dialog(f"Decrypted file saved to {decrypted_file_path}")
            messagebox.showinfo("Success", "File Decrypted Successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt the file: {e}")

    def update_dialog(self, message):
        """Update the dialog with a new message."""
        self.dialog_label.config(text=message)


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileVaultApp(root)
    root.mainloop()

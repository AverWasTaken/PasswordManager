

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
import string
import random
import json
import os
from cryptography.fernet import Fernet
import base64
import hashlib

# Define the main PasswordManager class
class PasswordManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Password Manager")
        self.data_file_path = "Data_Path_Here"
        self.master_password = self.get_master_password(setup=not self.data_file_exists())
        if not self.master_password:
            self.root.destroy()
            raise SystemExit("No master password provided.")
        self.setup_ui()

    def setup_ui(self):
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TButton", padding=6, relief="flat", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        self.style.configure("Treeview", highlightthickness=0, bd=0, font=('Arial', 11))
        self.style.configure("Treeview.Heading", font=('Arial', 12, 'bold'))
        self.style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])

        # Main layout frame
        frame = ttk.Frame(self.root, padding="10")
        frame.pack(expand=True, fill='both')

        # Search bar
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill='x', pady=5)
        ttk.Label(search_frame, text="Search:").pack(side='left', padx=(0, 10))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side='left', fill='x', expand=True)
        search_entry.bind("<KeyRelease>", self.filter_list)

        # Treeview for passwords
        self.listbox = ttk.Treeview(frame, columns=("Username", "Password"), show="headings")
        self.listbox.heading("Username", text="Username")
        self.listbox.heading("Password", text="Password")
        self.listbox.pack(expand=True, fill='both', padx=5, pady=5)
        self.listbox.bind("<Double-1>", self.copy_password)

        # Scrollbar
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        # Button frame
        button_frame = ttk.Frame(self.root, padding="10")
        button_frame.pack(fill='x')
        ttk.Button(button_frame, text="Create Password", command=self.create_or_import_passwords).pack(side='left', fill='x', expand=True, padx=2)
        ttk.Button(button_frame, text="Delete Password", command=self.delete_password).pack(side='left', fill='x', expand=True, padx=2)
        ttk.Button(button_frame, text="Copy Password", command=self.copy_password).pack(side='left', fill='x', expand=True, padx=2)

        self.populate_listbox()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def populate_listbox(self):
        for entry in self.load_data():
            self.listbox.insert("", "end", values=(entry["username"], entry["password"]))

    def filter_list(self, event):
        search_term = self.search_var.get().lower()
        self.listbox.delete(*self.listbox.get_children())  # Clear the treeview first

        if not search_term:
            # If the search bar is cleared, repopulate with all entries
            self.populate_listbox()
        else:
            # Repopulate the treeview with filtered data based on the search term
            for entry in self.load_data():
                username, password = entry["username"], entry["password"]
                if search_term in username.lower() or search_term in password.lower():
                    self.listbox.insert("", "end", values=(username, password))

    def data_file_exists(self):
        return os.path.exists(self.data_file_path) and os.path.getsize(self.data_file_path) > 0


    # Prompt for the master password
    def get_master_password(self, setup=False):
        if setup:
            # Prompt for setting up a new master password
            password = simpledialog.askstring("Setup", "Set Master Password:", show="*")
            confirm_password = simpledialog.askstring("Setup", "Confirm Master Password:", show="*")
            if password and confirm_password and password == confirm_password:
                return password
            else:
                messagebox.showerror("Error", "Passwords do not match. Please try again.")
                return self.get_master_password(setup=True)
        else:
            # Prompt for entering an existing master password
            return simpledialog.askstring("Password Manager", "Enter Master Password:", show="*")

    # Load stored password data
    def load_data(self):
        try:
            with open(self.data_file_path, "r") as file:
                encrypted_data = file.read()
                if encrypted_data:
                    decrypted_data = self.decrypt_data(encrypted_data)
                    return json.loads(decrypted_data)
        except Exception as e:
            messagebox.showerror("Error", "Wrong password.")
            self.root.destroy()
            raise SystemExit("Wrong password provided.")
        return []

    # Save password data
    def save_data(self, data):
        try:
            os.makedirs(os.path.dirname(self.data_file_path), exist_ok=True)
            with open(self.data_file_path, "w") as file:
                encrypted_data = self.encrypt_data(json.dumps(data))
                file.write(encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save data: {e}")

    # Copy selected password to clipboard
    def copy_password(self, event=None):
        selected_item = self.listbox.selection()
        if selected_item:
            item = self.listbox.item(selected_item)
            password = item['values'][1]
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()
            messagebox.showinfo("Copied", "Copied Password!")

    # Delete selected password
    def delete_password(self):
        selected_item = self.listbox.selection()
        if selected_item:
            response = messagebox.askyesno("Confirm Delete", "Are you sure?")
            if response:
                item = self.listbox.item(selected_item)
                username = item['values'][0]
                self.listbox.delete(selected_item)
                data = self.load_data()
                data = [entry for entry in data if entry["username"] != username]
                self.save_data(data)

    # Create or import passwords
    def create_or_import_passwords(self):
        dialog = ImportDialog(self.root, self.generate_password)
        if dialog.result:
            username, password = dialog.result
            current_data = self.load_data()
            if any(entry['username'] == username for entry in current_data):
                messagebox.showwarning("Warning", "Username already exists.")
                return
            self.listbox.insert("", "end", values=(username, password))
            current_data.append({"username": username, "password": password})
            self.save_data(current_data)

    # Handle application close event
    def on_close(self):
        self.save_data(self.load_data())
        self.root.destroy()

    # Generate a random password
    def generate_password(self):
        characters = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(random.choice(characters) for _ in range(random.randint(12, 20)))

    # Generate a Fernet key from the master password
    def generate_key(self):
        return base64.urlsafe_b64encode(hashlib.sha256(self.master_password.encode()).digest())

    # Encrypt data using the master password
    def encrypt_data(self, data):
        key = self.generate_key()
        fernet = Fernet(key)
        return fernet.encrypt(data.encode()).decode()

    # Decrypt data using the master password
    def decrypt_data(self, data):
        key = self.generate_key()
        fernet = Fernet(key)
        return fernet.decrypt(data.encode()).decode()

# Define the ImportDialog class for creating or importing new passwords
class ImportDialog(simpledialog.Dialog):
    def __init__(self, parent, generate_password_func):
        self.generate_password = generate_password_func
        super().__init__(parent)

    def body(self, master):
        # Create input fields for username and password
        ttk.Label(master, text="Username:").grid(row=0)
        ttk.Label(master, text="Password:").grid(row=1)

        self.entry_username = ttk.Entry(master)
        self.entry_password = ttk.Entry(master, show="*")
        generate_btn = ttk.Button(master, text="Generate", command=self.on_generate)

        self.entry_username.grid(row=0, column=1)
        self.entry_password.grid(row=1, column=1)
        generate_btn.grid(row=1, column=2)

        return self.entry_username

    def on_generate(self):
        # Generate a random password and fill it in the password field
        password = self.generate_password()
        self.entry_password.delete(0, tk.END)
        self.entry_password.insert(0, password)

    def apply(self):
        # Store the entered username and password when the dialog is closed
        self.result = (self.entry_username.get(), self.entry_password.get())

# Main application entry point
if __name__ == "__main__":
    app = PasswordManager()
    app.root.mainloop()

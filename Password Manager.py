# IMPORTS
import customtkinter as ctk
import os
import base64
import hashlib
from tkinter import Listbox, Scrollbar
from tkinter import messagebox, Listbox, Scrollbar
from cryptography.fernet import Fernet


# KEY FILES 
KEY_FILE = "key.key"
CREDENTIALS_FILE = "savedcredentials.txt"


# LOAD/GENERATE KEY
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

# LOAD THE KEY
key = load_or_create_key()
fernet = Fernet(key)

# ENCRYPTED PASSWORD
def encrypt_password(password):
    return fernet.encrypt(password.encode()).decode()

# DECRYPTED PASSWORD
def decrypt_password(enc_password):
    return fernet.decrypt(enc_password.encode()).decode()



# Configure CTk
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Files
CREDENTIALS_FILE = "savedcredentials.txt"
USER_CREDENTIALS_FILE = "user_credentials.txt"
PIN_FILE = "pin.hash"
KEY_FILE = "key.key"



# --- ENCRYPTION --- #
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, 'rb') as f:
        return f.read()


# --- PIN --- #
def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()

def is_pin_set():
    return os.path.exists(PIN_FILE)

def verify_pin(input_pin):
    if not is_pin_set():
        return False
    with open(PIN_FILE, 'r') as f:
        stored_hash = f.read()
    return stored_hash == hash_pin(input_pin)

def set_pin(pin):
    with open(PIN_FILE, 'w') as f:
        f.write(hash_pin(pin))


# --- PIN Prompt  --- #
def prompt_for_pin(callback):
    def submit():
        pin = pin_entry.get()
        if verify_pin(pin):
            pin_window.destroy()
            callback(True)
        else:
            attempts[0] += 1
            if attempts[0] >= 5:
                pin_window.destroy()
                messagebox.showerror("Error", "Too many failed attempts.")
            else:
                pin_label.configure(text="Incorrect PIN. Try again.")

    attempts = [0]
    pin_window = ctk.CTkToplevel(app)
    pin_window.title("Enter PIN")
    pin_window.geometry("300x150")
    pin_label = ctk.CTkLabel(pin_window, text="Enter your PIN")
    pin_label.pack(pady=10)
    pin_entry = ctk.CTkEntry(pin_window, show="*")
    pin_entry.pack(pady=5)
    submit_btn = ctk.CTkButton(pin_window, text="Submit", command=submit)
    submit_btn.pack(pady=5)

def prompt_to_register_pin(callback):
    def register():
        pin = pin_entry.get()
        confirm = confirm_entry.get()
        if pin != confirm or not pin:
            pin_label.configure(text="PINs do not match or empty.")
        else:
            set_pin(pin)
            pin_window.destroy()
            callback(True)

    pin_window = ctk.CTkToplevel(app)
    pin_window.title("Set PIN")
    pin_window.geometry("300x200")
    pin_label = ctk.CTkLabel(pin_window, text="Set a new PIN")
    pin_label.pack(pady=10)
    pin_entry = ctk.CTkEntry(pin_window, placeholder_text="Enter PIN", show="*")
    pin_entry.pack(pady=5)
    confirm_entry = ctk.CTkEntry(pin_window, placeholder_text="Confirm PIN", show="*")
    confirm_entry.pack(pady=5)
    submit_btn = ctk.CTkButton(pin_window, text="Register", command=register)
    submit_btn.pack(pady=5)



# REGISTER PIN
def request_pin(callback):
    if is_pin_set():
        prompt_for_pin(callback)
    else:
        prompt_to_register_pin(callback)



# App Window
app = ctk.CTk()
app.title("Password Manager")
app.geometry("550x550")

# ---------- PAGE FRAMES ---------- #
login_frame = ctk.CTkFrame(app)
register_frame = ctk.CTkFrame(app)
main_frame = ctk.CTkFrame(app)
add_frame = ctk.CTkFrame(app)
view_frame = ctk.CTkFrame(app)
edit_frame = ctk.CTkFrame(app)  


# ---------- PAGE SWITCHING ---------- #
def show_main():
    login_frame.pack_forget()
    register_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_add_password():
    main_frame.pack_forget()
    add_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_view_passwords():
    main_frame.pack_forget()
    view_frame.pack(fill="both", expand=True, padx=20, pady=20)
    load_credentials()

def show_register():
    login_frame.pack_forget()
    register_frame.pack(fill="both", expand=True, padx=20, pady=20)

def back_to_login():
    register_frame.pack_forget()
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_edit_passwords():
    main_frame.pack_forget()
    edit_frame.pack(fill="both", expand=True, padx=20, pady=20)
    load_credentials_listbox()

# ---------- NEWWWWWWW ---------- #
def logout():
    main_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    login_user_entry.delete(0, ctk.END)
    login_pass_entry.delete(0, ctk.END)
    login_error.configure(text="")  
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

# ---------- LOGIN & REGISTER LOGIC ---------- #
def check_login():
    username = login_user_entry.get().strip()
    password = login_pass_entry.get().strip()

    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, "r") as f:
            for line in f:
                saved_user, saved_pass = line.strip().split(",")
                if username == saved_user and password == saved_pass:
                    show_main()
                    return
    login_error.configure(text="Invalid credentials.")

def register_user():
    username = reg_user_entry.get().strip()
    password = reg_pass_entry.get().strip()
    confirm = reg_confirm_entry.get().strip()

    if not username or not password:
        reg_error.configure(text="All fields are required.")
    elif password != confirm:
        reg_error.configure(text="Passwords do not match.")
    else:
        if os.path.exists(USER_CREDENTIALS_FILE):
            with open(USER_CREDENTIALS_FILE, "r") as f:
                for line in f:
                    if username == line.strip().split(",")[0]:
                        reg_error.configure(text="Username already exists.")
                        return
        with open(USER_CREDENTIALS_FILE, "a") as f:
            f.write(f"{username},{password}\n")
        back_to_login()

# ---------- SAVE & CLEAR ---------- #
def save_credentials():
    entry_type = type_entry.get().strip()
    entry_email = email_entry.get().strip()
    entry_password = password_entry.get().strip()

    if entry_type and entry_email and entry_password:
        encrypted_password = encrypt_password(entry_password)
        with open(CREDENTIALS_FILE, "a") as f:
            f.write(f"{entry_type},{entry_email},{encrypted_password}\n")
        clear_inputs()
        messagebox.showinfo("Success", "Credentials saved securely.")
    else:
        messagebox.showwarning("Missing Fields", "Please fill in all fields.")

def clear_inputs():
    type_entry.delete(0, ctk.END)
    email_entry.delete(0, ctk.END)
    password_entry.delete(0, ctk.END)


# ---------- LOAD & DISPLAY CREDENTIALS ---------- #
def load_credentials():
    textbox.configure(state="normal")
    textbox.delete("0.0", ctk.END)

    if not os.path.exists(CREDENTIALS_FILE):
        textbox.insert(ctk.END, "No credentials file found.\n")
    else:
        with open(CREDENTIALS_FILE, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            textbox.insert(ctk.END, "No saved credentials.\n")
        else:
            for i, line in enumerate(lines, 1):
                parts = line.split(",")
                if len(parts) == 3:
                    entry_type, email, enc_password = parts
                    try:
                        password = decrypt_password(enc_password) if show_passwords[0] else "*****"
                    except:
                        password = "[Error decrypting]"
                    textbox.insert(ctk.END,
                        f"{i})\n"
                        f"Type:     {entry_type}\n"
                        f"Email:    {email}\n"
                        f"Password: {password}\n"
                        f"{'-'*40}\n"
                    )
                else:
                    textbox.insert(ctk.END, f"{i}) Malformed entry: {line}\n{'-'*40}\n")

    textbox.configure(state="disabled")


# ---------- EDIT PASSWORDS FUNCTIONALITY ---------- #

# Flag to toggle password visibility
show_passwords = [False]

# Toggle logic with PIN validation
def toggle_password_visibility():
    def after_pin(success):
        if success:
            show_passwords[0] = not show_passwords[0]
            visibility_switch.select() if show_passwords[0] else visibility_switch.deselect()
            load_credentials()
        else:
            # Revert switch if PIN failed
            visibility_switch.deselect()

    # Ask for PIN only if switching ON (revealing passwords)
    if not show_passwords[0]:
        request_pin(after_pin)
    else:
        show_passwords[0] = False
        load_credentials()

# Create the switch
visibility_switch = ctk.CTkSwitch(
    master=view_frame,
    text="Show Passwords",
    command=toggle_password_visibility
)
visibility_switch.pack(pady=5)


# CREDENTIALS IN "EDITING CREDENTIALS"
def load_credentials_listbox():
    listbox.delete(0, ctk.END)
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
            for i, line in enumerate(lines, 1):
                parts = line.split(",")
                if len(parts) == 3:
                    entry_type, email, enc_password = parts
                    try:
                        masked_password = "*****"
                    except:
                        masked_password = "[Error]"
                    display_text = (
                        f"{i}. Type: {entry_type} | Email: {email} | Password: {masked_password}"
                    )
                else:
                    display_text = f"{i}. Malformed entry"
                listbox.insert(ctk.END, display_text)


# DELETE SELECTED CREDENTIAL
def delete_selected():
    selected_indices = listbox.curselection()
    if not selected_indices:
        messagebox.showwarning("No selection", "Please select an entry to delete.")
        return
    index = selected_indices[0]
    listbox.delete(index)
    update_credentials_file()

# EDIT SELECTED CREDENTIAL
def edit_selected():
    def after_pin(success):
        if not success:
            return

        selected_indices = listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No selection", "Please select an entry to edit.")
            return
        index = selected_indices[0]

        # Read from file, not from listbox
        if not os.path.exists(CREDENTIALS_FILE):
            messagebox.showerror("Error", "Credentials file not found.")
            return

        with open(CREDENTIALS_FILE, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        if index >= len(lines):
            messagebox.showerror("Error", "Invalid selection.")
            return

        line = lines[index]
        parts = line.split(",")
        if len(parts) != 3:
            messagebox.showerror("Error", "Selected entry is malformed.")
            return
        entry_type, email, enc_password = parts

        try:
            password = decrypt_password(enc_password)
        except:
            password = ""

        # Create edit window
        edit_window = ctk.CTkToplevel(app)
        edit_window.title("Edit Entry")
        edit_window.geometry("400x300")

        type_label = ctk.CTkLabel(edit_window, text="Type:")
        type_label.pack(pady=5)
        type_entry = ctk.CTkEntry(edit_window)
        type_entry.insert(0, entry_type)
        type_entry.pack(pady=5)

        email_label = ctk.CTkLabel(edit_window, text="Email:")
        email_label.pack(pady=5)
        email_entry = ctk.CTkEntry(edit_window)
        email_entry.insert(0, email)
        email_entry.pack(pady=5)

        password_label = ctk.CTkLabel(edit_window, text="Password:")
        password_label.pack(pady=5)
        password_entry = ctk.CTkEntry(edit_window, show="*")
        password_entry.insert(0, "*****")  # Show only asterisks
        password_entry.pack(pady=5)

        def save_changes():
            new_type = type_entry.get().strip()
            new_email = email_entry.get().strip()
            new_password = password if password_entry.get() == "*****" else password_entry.get().strip()

            if not new_type or not new_email or not new_password:
                messagebox.showwarning("Incomplete Data", "All fields are required.")
                return

            encrypted_password = encrypt_password(new_password)
            lines[index] = f"{new_type},{new_email},{encrypted_password}"

            with open(CREDENTIALS_FILE, "w") as f:
                for line in lines:
                    f.write(line + "\n")

            load_credentials()
            edit_window.destroy()

        save_button = ctk.CTkButton(edit_window, text="Save Changes", command=save_changes)
        save_button.pack(pady=10)

    request_pin(after_pin)

def update_credentials_file():
    entries = listbox.get(0, ctk.END)
    with open(CREDENTIALS_FILE, "w") as f:
        for entry in entries:
            f.write(f"{entry}\n")



# ---------- LOGIN PAGE ---------- #
login_label = ctk.CTkLabel(login_frame, text="🔐 Login", font=ctk.CTkFont(size=32, weight="bold"))
login_label.pack(pady=20)

login_user_entry = ctk.CTkEntry(login_frame, placeholder_text="Username")
login_user_entry.pack(pady=10)

login_pass_entry = ctk.CTkEntry(login_frame, placeholder_text="Password", show="*")
login_pass_entry.pack(pady=10)

login_error = ctk.CTkLabel(login_frame, text="", text_color="red")
login_error.pack()

login_button = ctk.CTkButton(login_frame, text="Login", command=check_login)
login_button.pack(pady=10)

register_link = ctk.CTkButton(login_frame, text="Register", command=show_register)
register_link.pack(pady=5)


# ---------- REGISTER PAGE ---------- #
register_label = ctk.CTkLabel(register_frame, text="📝 Register", font=ctk.CTkFont(size=32, weight="bold"))
register_label.pack(pady=20)

reg_user_entry = ctk.CTkEntry(register_frame, placeholder_text="New Username")
reg_user_entry.pack(pady=10)

reg_pass_entry = ctk.CTkEntry(register_frame, placeholder_text="New Password", show="*")
reg_pass_entry.pack(pady=10)

reg_confirm_entry = ctk.CTkEntry(register_frame, placeholder_text="Confirm Password", show="*")
reg_confirm_entry.pack(pady=10)

reg_error = ctk.CTkLabel(register_frame, text="", text_color="red")
reg_error.pack()

reg_button = ctk.CTkButton(register_frame, text="Create Account", command=register_user)
reg_button.pack(pady=10)

back_login_btn = ctk.CTkButton(register_frame, text="Back to Login", command=back_to_login)
back_login_btn.pack(pady=5)


# ---------- MAIN PAGE ---------- #
main_label = ctk.CTkLabel(main_frame, text="🔐 Password Manager", font=ctk.CTkFont(size=32, weight="bold"))
main_label.pack(pady=20)

add_pass_btn = ctk.CTkButton(main_frame, text="Add Password", command=show_add_password)
add_pass_btn.pack(pady=10)

view_pass_btn = ctk.CTkButton(main_frame, text="View Passwords", command=show_view_passwords)
view_pass_btn.pack(pady=10)

edit_pass_btn = ctk.CTkButton(main_frame, text="Edit Passwords", command=show_edit_passwords)
edit_pass_btn.pack(pady=10)

logout_btn = ctk.CTkButton(main_frame, text="Logout", command=logout)
logout_btn.pack(pady=10)


# ---------- ADD PASSWORD PAGE ---------- #
add_label = ctk.CTkLabel(add_frame, text="➕ Add New Credential", font=ctk.CTkFont(size=24, weight="bold"))
add_label.pack(pady=10)

type_entry = ctk.CTkEntry(add_frame, placeholder_text="Type (e.g., Gmail, Netflix)")
type_entry.pack(pady=5)

email_entry = ctk.CTkEntry(add_frame, placeholder_text="Email/Username")
email_entry.pack(pady=5)

password_entry = ctk.CTkEntry(add_frame, placeholder_text="Password", show="*")
password_entry.pack(pady=5)

save_btn = ctk.CTkButton(add_frame, text="Save", command=save_credentials)
save_btn.pack(pady=10)

back_btn = ctk.CTkButton(add_frame, text="Back", command=show_main)
back_btn.pack(pady=5)


# ---------- VIEW PASSWORD PAGE ---------- #
view_label = ctk.CTkLabel(view_frame, text="📄 Saved Credentials", font=ctk.CTkFont(size=24, weight="bold"))
view_label.pack(pady=10)

textbox = ctk.CTkTextbox(view_frame, width=500, height=350, wrap="word", state="disabled")
textbox.pack(pady=10)

back_view_btn = ctk.CTkButton(view_frame, text="Back", command=show_main)
back_view_btn.pack(pady=5)


# ---------- EDIT PASSWORD PAGE ---------- #
edit_label = ctk.CTkLabel(edit_frame, text="✏️ Edit Credentials", font=ctk.CTkFont(size=24, weight="bold"))
edit_label.pack(pady=10)

listbox_frame = ctk.CTkFrame(edit_frame)
listbox_frame.pack(pady=10, fill="both", expand=True)

scrollbar = Scrollbar(listbox_frame)
scrollbar.pack(side="right", fill="y")

listbox = Listbox(listbox_frame, yscrollcommand=scrollbar.set, width=60, height=15, font=("Courier", 12))
listbox.pack(side="left", fill="both", expand=True)

scrollbar.config(command=listbox.yview)

edit_button = ctk.CTkButton(edit_frame, text="Edit Selected", command=edit_selected)
edit_button.pack(pady=5)

delete_button = ctk.CTkButton(edit_frame, text="Delete Selected", command=delete_selected)
delete_button.pack(pady=5)

back_edit_btn = ctk.CTkButton(edit_frame, text="Back", command=show_main)
back_edit_btn.pack(pady=5)


# ---------- START THE APP ---------- #
login_frame.pack(fill="both", expand=True, padx=20, pady=20)

app.mainloop()

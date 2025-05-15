# IMPORTS
import customtkinter as ctk
import os
import base64
import hashlib
from tkinter import messagebox, Listbox, Scrollbar
from cryptography.fernet import Fernet
from PIL import Image, ImageDraw
import random
import string


# KEY FILES 
KEY_FILE = "key.key"
CREDENTIALS_FILE = "savedcredentials.txt"

# USER-SPECIFIC FILES
CURRENT_USER = [None]  # Use a list for mutability in nested functions

def get_user_files(username):
    return {
        'CREDENTIALS_FILE': f"{username}_credentials.txt",
        'PIN_FILE': f"{username}_pin.hash",
        'KEY_FILE': f"{username}_key.key"
    }

# --- PIN --- #
def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()

def is_pin_set():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    return os.path.exists(files['PIN_FILE']) and os.path.getsize(files['PIN_FILE']) > 0

def verify_pin(input_pin):
    username = CURRENT_USER[0]
    files = get_user_files(username)
    if not is_pin_set():
        return False
    with open(files['PIN_FILE'], 'r') as f:
        stored_hash = f.read()
    return stored_hash == hash_pin(input_pin)

def set_pin(pin):
    username = CURRENT_USER[0]
    files = get_user_files(username)
    with open(files['PIN_FILE'], 'w') as f:
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


# --- ENCRYPTION --- #
def generate_key(username):
    key = Fernet.generate_key()  # Generate a unique key
    files = get_user_files(username)
    with open(files['KEY_FILE'], "wb") as key_file:  # Save the key to a file
        key_file.write(key)
    return key

# Function to load an existing key from a file
def load_key(username):
    files = get_user_files(username)
    try:
        with open(files['KEY_FILE'], "rb") as key_file:
            key = key_file.read()  # Read the key from the file
        return key
    except FileNotFoundError:
        print(f"No key file found for user {username}.")
        return None

# Function to encrypt data using the user's key
def encrypt_data(data, username):
    key = load_key(username)
    if key is None:
        key = generate_key(username)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()  # Store as string

# Function to decrypt data using the user's key
def decrypt_data(encrypted_data, username):
    key = load_key(username)
    if key is None:
        print(f"No key file found for user {username}.")
        return None
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data.encode())  # Convert back to bytes
    return decrypted_data.decode()

# Configure CTk
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Files
CREDENTIALS_FILE = "savedcredentials.txt"
USER_CREDENTIALS_FILE = "user_credentials.txt"
PIN_FILE = "pin.hash"
KEY_FILE = "key.key"



# App Window
app = ctk.CTk()
app.title("Password Manager")
app.geometry("600x750")

# ---------- PAGE FRAMES ---------- #
login_frame = ctk.CTkFrame(app)
register_frame = ctk.CTkFrame(app)
main_frame = ctk.CTkFrame(app)
add_frame = ctk.CTkFrame(app)
view_frame = ctk.CTkFrame(app)
edit_frame = ctk.CTkFrame(app)  
opening_frame = ctk.CTkFrame(app)

# Set all main frames' background color to white
login_frame.configure(fg_color="white")
register_frame.configure(fg_color="white")
main_frame.configure(fg_color="white")
add_frame.configure(fg_color="white")
view_frame.configure(fg_color="white")
edit_frame.configure(fg_color="white")
opening_frame.configure(fg_color="white")

# ---------- PAGE SWITCHING ---------- #
def show_main():
    login_frame.pack_forget()
    register_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    main_frame.pack(fill="both", expand=True, padx=0, pady=0)
    refresh_main_credentials()

def show_add_password():
    # Reset save/back buttons to add mode
    save_btn.configure(text="Save", command=save_credentials)
    back_btn.configure(text="Back", command=show_main)
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
    CURRENT_USER[0] = None
    main_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    try:
        login_user_entry.delete(0, ctk.END)
        login_pass_entry.delete(0, ctk.END)
    except Exception:
        pass
    login_error.configure(text="")  
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

# --- VALIDATION FUNCTIONS --- #
def validate_username(username):
    if not (6 <= len(username) <= 20):
        return False, "Username must be between 6 and 20 characters."
    return True, ""

def validate_password(password):
    if not (6 <= len(password) <= 20):
        return False, "Password must be between 6 and 20 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character."
    return True, ""

# ---------- LOGIN & REGISTER LOGIC ---------- #
def check_login():
    username = login_user_entry.get().strip()
    password = login_pass_entry.get().strip()

    # Validate username length
    if not (6 <= len(username) <= 20):
        login_error.configure(text="Username must be between 6 and 20 characters.")
        return

    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, "r") as f:
            for line in f:
                saved_user, saved_pass = line.strip().split(",")
                if username == saved_user and password == saved_pass:
                    CURRENT_USER[0] = username
                    # Initialize user files if they don't exist
                    files = get_user_files(username)
                    if not os.path.exists(files['CREDENTIALS_FILE']):
                        open(files['CREDENTIALS_FILE'], 'w').close()
                    if not os.path.exists(files['KEY_FILE']):
                        generate_key(username)
                    login_count = increment_login_count(username)
                    def after_mfa():
                        show_main()
                    if login_count % 3 == 0:
                        show_mfa_verify_prompt_in_frame(username, login_frame, after_mfa)
                    else:
                        show_main()
                    return
    login_error.configure(text="Invalid credentials.")

def register_user():
    username = reg_user_entry.get().strip()
    password = reg_pass_entry.get().strip()
    confirm = reg_confirm_entry.get().strip()

    # Validate username
    username_valid, username_error = validate_username(username)
    if not username_valid:
        reg_error.configure(text=username_error)
        return

    # Validate password
    password_valid, password_error = validate_password(password)
    if not password_valid:
        reg_error.configure(text=password_error)
        return

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
        
        # Create user-specific files
        files = get_user_files(username)
        open(files['CREDENTIALS_FILE'], 'w').close()  # Create empty credentials file
        generate_key(username)  # Generate encryption key for the user
        
        # Save user credentials
        with open(USER_CREDENTIALS_FILE, "a") as f:
            f.write(f"{username},{password}\n")
        
        CURRENT_USER[0] = username
        show_mfa_prompt_in_frame(username, register_frame, back_to_login)

# --- MFA PROMPT (IN-FRAME) --- #
def show_mfa_prompt_in_frame(username, parent_frame, on_success):
    for widget in parent_frame.winfo_children():
        widget.destroy()
    parent_frame.configure(fg_color="white")

    # Logo at the top
    mfa_logo_image = ctk.CTkImage(light_image=Image.open("Logo2.png"), size=(120, 90))
    mfa_logo_label = ctk.CTkLabel(parent_frame, image=mfa_logo_image, text="", text_color="black")
    mfa_logo_label.pack(pady=(30, 10))

    # Title
    mfa_title = ctk.CTkLabel(parent_frame, text="Just a few more steps!", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"), text_color="black")
    mfa_title.pack(pady=(0, 8))

    # Description
    mfa_desc = ctk.CTkLabel(parent_frame, text="For authentication purposes,\nPlace a personal question and an answer\nonly you'd most likely know.", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=14), text_color="black", justify="center")
    mfa_desc.pack(pady=(0, 18))

    # Question entry
    question_entry = ctk.CTkEntry(parent_frame, placeholder_text="Enter Question", fg_color="#f0f0f0", text_color="black", placeholder_text_color="black")
    question_entry.pack(pady=10, ipadx=4, ipady=4)

    # Answer entry
    answer_entry = ctk.CTkEntry(parent_frame, placeholder_text="Enter Answer", fg_color="#f0f0f0", text_color="black", placeholder_text_color="black")
    answer_entry.pack(pady=10, ipadx=4, ipady=4)

    # Error/success label
    mfa_error = ctk.CTkLabel(parent_frame, text="", text_color="red")
    mfa_error.pack(pady=(0, 5))

    def save_mfa():
        question = question_entry.get().strip()
        answer = answer_entry.get().strip()
        if not question or not answer:
            mfa_error.configure(text="Both fields are required!", text_color="red")
            return
        files = get_user_files(username)
        mfa_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_mfa.txt')
        with open(mfa_file, 'w') as f:
            f.write(question + '\n')
            f.write(answer + '\n')
        mfa_error.configure(text="MFA question set!", text_color="green")
        parent_frame.after(1000, on_success)

    # Save button
    save_btn = ctk.CTkButton(parent_frame, text="SAVE", width=220, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), command=save_mfa, text_color="white")
    save_btn.pack(pady=(18, 8))

# --- MFA VERIFY PROMPT (IN-FRAME) --- #
def show_mfa_verify_prompt_in_frame(username, parent_frame, on_success):
    for widget in parent_frame.winfo_children():
        widget.destroy()
    parent_frame.configure(fg_color="white")

    files = get_user_files(username)
    mfa_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_mfa.txt')
    if not os.path.exists(mfa_file):
        on_success()
        return
    with open(mfa_file, 'r') as f:
        question = f.readline().strip()
        correct_answer = f.readline().strip()

    # Logo at the top
    mfa_logo_image = ctk.CTkImage(light_image=Image.open("Logo2.png"), size=(120, 90))
    mfa_logo_label = ctk.CTkLabel(parent_frame, image=mfa_logo_image, text="", text_color="black")
    mfa_logo_label.pack(pady=(30, 10))

    # Title
    mfa_title = ctk.CTkLabel(parent_frame, text="Just a few more steps!", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"), text_color="black")
    mfa_title.pack(pady=(0, 8))

    # Description
    mfa_desc = ctk.CTkLabel(parent_frame, text="To make sure your account is safe.", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=14), text_color="black", justify="center")
    mfa_desc.pack(pady=(0, 18))

    # The user's MFA question (bold)
    mfa_question = ctk.CTkLabel(parent_frame, text=question, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), text_color="black")
    mfa_question.pack(pady=(0, 8))

    # Answer entry
    answer_entry = ctk.CTkEntry(parent_frame, placeholder_text="Enter Answer", fg_color="#f0f0f0", text_color="black", placeholder_text_color="black", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=18))
    answer_entry.pack(pady=10, ipadx=4, ipady=4)

    # Error label
    mfa_error = ctk.CTkLabel(parent_frame, text="", text_color="red")
    mfa_error.pack(pady=(0, 5))

    def check_answer():
        answer = answer_entry.get().strip()
        if answer.strip().lower() == correct_answer.strip().lower():
            mfa_error.configure(text="Correct!", text_color="green")
            parent_frame.after(500, on_success)
        else:
            mfa_error.configure(text="Incorrect answer. Try again.", text_color="red")

    def go_back():
        back_to_login()

    # LOGIN button
    login_btn = ctk.CTkButton(parent_frame, text="LOGIN", width=220, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), command=check_answer, text_color="white")
    login_btn.pack(pady=(18, 8))

    # GO BACK button
    back_btn = ctk.CTkButton(parent_frame, text="GO BACK", width=220, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), command=go_back, text_color="white")
    back_btn.pack(pady=(0, 8))

# ---------- SAVE & CLEAR ---------- #
def save_credentials():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    category = category_entry.get().strip()
    
    if category == "Login":
        entry_type = type_entry.get().strip()
        entry_email = email_entry.get().strip()
        entry_password = password_entry.get().strip()
        
        if not all([entry_type, entry_email, entry_password]):
            messagebox.showwarning("Missing Fields", "Please fill in all fields.")
            return
            
        encrypted_password = encrypt_data(entry_password, username)
        with open(files['CREDENTIALS_FILE'], "a") as f:
            f.write(f"Login|{entry_type}|{entry_email}|{encrypted_password}\n")
            
    elif category == "Credit Card":
        card_name = card_name_entry.get().strip()
        card_number = card_number_entry.get().strip()
        card_expiry = card_expiry_entry.get().strip()
        card_cvv = card_cvv_entry.get().strip()
        
        if not all([card_name, card_number, card_expiry, card_cvv]):
            messagebox.showwarning("Missing Fields", "Please fill in all card fields.")
            return
            
        encrypted_cvv = encrypt_data(card_cvv, username)
        with open(files['CREDENTIALS_FILE'], "a") as f:
            f.write(f"Credit Card|{card_name}|{card_number}|{card_expiry}|{encrypted_cvv}\n")
            
    elif category == "Notes":
        title = notes_title_entry.get().strip()
        content = notes_content.get("1.0", ctk.END).strip()
        
        if not all([title, content]):
            messagebox.showwarning("Missing Fields", "Please fill in title and content.")
            return
            
        encrypted_content = encrypt_data(content, username)
        with open(files['CREDENTIALS_FILE'], "a") as f:
            f.write(f"Notes|{title}|{encrypted_content}\n")
    
    clear_inputs()
    messagebox.showinfo("Success", "Credentials saved securely.")

def clear_inputs():
    type_entry.delete(0, ctk.END)
    email_entry.delete(0, ctk.END)
    password_entry.delete(0, ctk.END)
    card_name_entry.delete(0, ctk.END)
    card_number_entry.delete(0, ctk.END)
    card_expiry_entry.delete(0, ctk.END)
    card_cvv_entry.delete(0, ctk.END)
    notes_title_entry.delete(0, ctk.END)
    notes_content.delete("1.0", ctk.END)


# ---------- LOAD & DISPLAY CREDENTIALS ---------- #
def load_credentials():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    textbox.configure(state="normal")
    textbox.delete("0.0", ctk.END)

    if not os.path.exists(files['CREDENTIALS_FILE']):
        textbox.insert(ctk.END, "No credentials file found.\n")
    else:
        with open(files['CREDENTIALS_FILE'], "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            textbox.insert(ctk.END, "No saved credentials.\n")
        else:
            # Group credentials by category
            credentials_by_category = {}
            for line in lines:
                parts = line.split("|")
                if len(parts) >= 2:
                    category = parts[0]
                    if category not in credentials_by_category:
                        credentials_by_category[category] = []
                    credentials_by_category[category].append(parts[1:])

            # Get selected category filter
            selected_category = category_filter.get()

            # Display credentials by category
            for category in ["Login", "Credit Card", "Notes"]:
                # Skip if filtering and not matching category
                if selected_category != "All" and category != selected_category:
                    continue
                    
                if category in credentials_by_category:
                    textbox.insert(ctk.END, f"\n=== {category} ===\n\n")
                    for i, parts in enumerate(credentials_by_category[category], 1):
                        if category == "Login":
                            entry_type, email, enc_password = parts
                            try:
                                password = decrypt_data(enc_password, username) if show_passwords[0] else "*****"
                            except:
                                password = "[Error decrypting]"
                            textbox.insert(ctk.END,
                                f"{i})\n"
                                f"Type:     {entry_type}\n"
                                f"Email:    {email}\n"
                                f"Password: {password}\n"
                                f"{'-'*40}\n"
                            )
                        elif category == "Credit Card":
                            card_name, card_number, card_expiry, enc_cvv = parts
                            try:
                                cvv = decrypt_data(enc_cvv, username) if show_passwords[0] else "*****"
                            except:
                                cvv = "[Error decrypting]"
                            textbox.insert(ctk.END,
                                f"{i})\n"
                                f"Name:     {card_name}\n"
                                f"Number:   {card_number}\n"
                                f"Expiry:   {card_expiry}\n"
                                f"CVV:      {cvv}\n"
                                f"{'-'*40}\n"
                            )
                        elif category == "Notes":
                            title, enc_content = parts
                            try:
                                content = decrypt_data(enc_content, username) if show_passwords[0] else "*****"
                            except:
                                content = "[Error decrypting]"
                            textbox.insert(ctk.END,
                                f"{i})\n"
                                f"Title:    {title}\n"
                                f"Content:  {content}\n"
                                f"{'-'*40}\n"
                            )

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
    username = CURRENT_USER[0]
    files = get_user_files(username)
    listbox.delete(0, ctk.END)
    if os.path.exists(files['CREDENTIALS_FILE']):
        with open(files['CREDENTIALS_FILE'], "r") as f:
            lines = [line.strip() for line in f if line.strip()]
            
            # Group credentials by category
            credentials_by_category = {}
            
            for line in lines:
                parts = line.split("|")
                if len(parts) >= 2:
                    category = parts[0]
                    if category not in credentials_by_category:
                        credentials_by_category[category] = []
                    credentials_by_category[category].append(parts[1:])

            # Get selected category filter
            selected_category = edit_category_filter.get()

            # Display credentials by category
            for category in ["Login", "Credit Card", "Notes"]:
                # Skip if filtering and not matching category
                if selected_category != "All" and category != selected_category:
                    continue
                    
                if category in credentials_by_category:
                    listbox.insert(ctk.END, f"=== {category} ===")
                    for parts in credentials_by_category[category]:
                        try:
                            if category == "Login":
                                entry_type, email, enc_password = parts
                                display_text = f"Type: {entry_type} | Email: {email} | Password: *****"
                                listbox.insert(ctk.END, display_text)
                            elif category == "Credit Card":
                                card_name, card_number, card_expiry, enc_cvv = parts
                                display_text = f"Name: {card_name} | Number: {card_number} | Expiry: {card_expiry} | CVV: *****"
                                listbox.insert(ctk.END, display_text)
                            elif category == "Notes":
                                title, enc_content = parts
                                display_text = f"Title: {title} | Content: *****"
                                listbox.insert(ctk.END, display_text)
                        except Exception as e:
                            print(f"Error processing entry: {e}")
                            continue
                    listbox.insert(ctk.END, "")  # Add empty line between categories


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

        # Get the selected text
        selected_text = listbox.get(index)
        
        # Skip if it's a category header or empty line
        if selected_text.startswith("===") or not selected_text.strip():
            messagebox.showwarning("Invalid Selection", "Please select an actual entry to edit.")
            return

        # Read from file
        username = CURRENT_USER[0]
        files = get_user_files(username)
        if not os.path.exists(files['CREDENTIALS_FILE']):
            messagebox.showerror("Error", "Credentials file not found.")
            return

        with open(files['CREDENTIALS_FILE'], "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        # Find the matching entry
        selected_line = None
        current_category = None

        for line in lines:
            parts = line.split("|")
            if len(parts) >= 2:
                category = parts[0]
                if category in ["Login", "Credit Card", "Notes"]:
                    # Create display text for comparison
                    if category == "Login":
                        entry_type, email, _ = parts[1:]
                        display_text = f"Type: {entry_type} | Email: {email} | Password: *****"
                    elif category == "Credit Card":
                        card_name, card_number, card_expiry, _ = parts[1:]
                        display_text = f"Name: {card_name} | Number: {card_number} | Expiry: {card_expiry} | CVV: *****"
                    elif category == "Notes":
                        title, _ = parts[1:]
                        display_text = f"Title: {title} | Content: *****"
                    
                    if display_text == selected_text:
                        selected_line = line
                        current_category = category
                        break

        if not selected_line:
            messagebox.showerror("Error", "Could not find the selected entry.")
            return

        parts = selected_line.split("|")
        if len(parts) < 2:
            messagebox.showerror("Error", "Selected entry is malformed.")
            return
            
        category = current_category
        
        # Create edit window
        edit_window = ctk.CTkToplevel(app)
        edit_window.title("Edit Entry")
        edit_window.geometry("400x350")

        if category == "Login":
            entry_type, email, enc_password = parts[1:]
            try:
                password = decrypt_data(enc_password, username)
            except:
                password = ""

            category_label = ctk.CTkLabel(edit_window, text="Category:")
            category_label.pack(pady=5)
            category_entry = ctk.CTkOptionMenu(edit_window, values=["Login"])
            category_entry.set(category)
            category_entry.pack(pady=5)

            type_label = ctk.CTkLabel(edit_window, text="Type:")
            type_label.pack(pady=5)
            type_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            type_entry.insert(0, entry_type)
            type_entry.pack(pady=5)

            email_label = ctk.CTkLabel(edit_window, text="Email:")
            email_label.pack(pady=5)
            email_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            email_entry.insert(0, email)
            email_entry.pack(pady=5)

            password_label = ctk.CTkLabel(edit_window, text="Password:")
            password_label.pack(pady=5)
            password_entry = ctk.CTkEntry(edit_window, show="*", fg_color="#f0f0f0")
            password_entry.insert(0, "*****")
            password_entry.pack(pady=5)

            def save_changes():
                new_type = type_entry.get().strip()
                new_email = email_entry.get().strip()
                new_password = password if password_entry.get() == "*****" else password_entry.get().strip()

                if not new_type or not new_email or not new_password:
                    messagebox.showwarning("Incomplete Data", "All fields are required.")
                    return

                encrypted_password = encrypt_data(new_password, username)
                new_line = f"Login|{new_type}|{new_email}|{encrypted_password}"
                
                # Update the file
                with open(files['CREDENTIALS_FILE'], "r") as f:
                    all_lines = f.readlines()
                
                # Find and replace the line
                for i, line in enumerate(all_lines):
                    if line.strip() == selected_line:
                        all_lines[i] = new_line + "\n"
                        break
                
                with open(files['CREDENTIALS_FILE'], "w") as f:
                    f.writelines(all_lines)

                load_credentials_listbox()
                edit_window.destroy()

        elif category == "Credit Card":
            card_name, card_number, card_expiry, enc_cvv = parts[1:]
            try:
                cvv = decrypt_data(enc_cvv, username)
            except:
                cvv = ""

            category_label = ctk.CTkLabel(edit_window, text="Category:")
            category_label.pack(pady=5)
            category_entry = ctk.CTkOptionMenu(edit_window, values=["Credit Card"])
            category_entry.set(category)
            category_entry.pack(pady=5)

            name_label = ctk.CTkLabel(edit_window, text="Name on Card:")
            name_label.pack(pady=5)
            name_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            name_entry.insert(0, card_name)
            name_entry.pack(pady=5)

            number_label = ctk.CTkLabel(edit_window, text="Card Number:")
            number_label.pack(pady=5)
            number_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            number_entry.insert(0, card_number)
            number_entry.pack(pady=5)

            expiry_label = ctk.CTkLabel(edit_window, text="Expiry Date:")
            expiry_label.pack(pady=5)
            expiry_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            expiry_entry.insert(0, card_expiry)
            expiry_entry.pack(pady=5)

            cvv_label = ctk.CTkLabel(edit_window, text="CVV:")
            cvv_label.pack(pady=5)
            cvv_entry = ctk.CTkEntry(edit_window, show="*", fg_color="#f0f0f0")
            cvv_entry.insert(0, "*****")
            cvv_entry.pack(pady=5)

            def save_changes():
                new_name = name_entry.get().strip()
                new_number = number_entry.get().strip()
                new_expiry = expiry_entry.get().strip()
                new_cvv = cvv if cvv_entry.get() == "*****" else cvv_entry.get().strip()

                if not all([new_name, new_number, new_expiry, new_cvv]):
                    messagebox.showwarning("Incomplete Data", "All fields are required.")
                    return

                encrypted_cvv = encrypt_data(new_cvv, username)
                new_line = f"Credit Card|{new_name}|{new_number}|{new_expiry}|{encrypted_cvv}"
                
                # Update the file
                with open(files['CREDENTIALS_FILE'], "r") as f:
                    all_lines = f.readlines()
                
                # Find and replace the line
                for i, line in enumerate(all_lines):
                    if line.strip() == selected_line:
                        all_lines[i] = new_line + "\n"
                        break
                
                with open(files['CREDENTIALS_FILE'], "w") as f:
                    f.writelines(all_lines)

                load_credentials_listbox()
                edit_window.destroy()

        elif category == "Notes":
            title, enc_content = parts[1:]
            try:
                content = decrypt_data(enc_content, username)
            except:
                content = ""

            category_label = ctk.CTkLabel(edit_window, text="Category:")
            category_label.pack(pady=5)
            category_entry = ctk.CTkOptionMenu(edit_window, values=["Notes"])
            category_entry.set(category)
            category_entry.pack(pady=5)

            title_label = ctk.CTkLabel(edit_window, text="Title:")
            title_label.pack(pady=5)
            title_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            title_entry.insert(0, title)
            title_entry.pack(pady=5)

            content_label = ctk.CTkLabel(edit_window, text="Content:")
            content_label.pack(pady=5)
            content_entry = ctk.CTkTextbox(edit_window, width=300, height=150, fg_color="#f0f0f0")
            content_entry.insert("1.0", content)
            content_entry.pack(pady=5)

            def save_changes():
                new_title = title_entry.get().strip()
                new_content = content_entry.get("1.0", ctk.END).strip()

                if not all([new_title, new_content]):
                    messagebox.showwarning("Incomplete Data", "All fields are required.")
                    return

                encrypted_content = encrypt_data(new_content, username)
                new_line = f"Notes|{new_title}|{encrypted_content}"
                
                # Update the file
                with open(files['CREDENTIALS_FILE'], "r") as f:
                    all_lines = f.readlines()
                
                # Find and replace the line
                for i, line in enumerate(all_lines):
                    if line.strip() == selected_line:
                        all_lines[i] = new_line + "\n"
                        break
                
                with open(files['CREDENTIALS_FILE'], "w") as f:
                    f.writelines(all_lines)

                load_credentials_listbox()
                edit_window.destroy()

        save_button = ctk.CTkButton(edit_window, text="Save Changes", command=save_changes)
        save_button.pack(pady=10)

    request_pin(after_pin)

def update_credentials_file():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    entries = listbox.get(0, ctk.END)
    with open(files['CREDENTIALS_FILE'], "w") as f:
        for entry in entries:
            f.write(f"{entry}\n")

def get_login_count(username):
    files = get_user_files(username)
    count_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_login_count.txt')
    if not os.path.exists(count_file):
        return 0
    with open(count_file, 'r') as f:
        try:
            return int(f.read().strip())
        except:
            return 0

def increment_login_count(username):
    files = get_user_files(username)
    count_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_login_count.txt')
    count = get_login_count(username) + 1
    with open(count_file, 'w') as f:
        f.write(str(count))
    return count

# ---------- LOGIN PAGE ---------- #
for widget in login_frame.winfo_children():
    widget.destroy()

# Logo at the top
login_logo_image = ctk.CTkImage(light_image=Image.open("Logo2.png"), size=(120, 90))
login_logo_label = ctk.CTkLabel(login_frame, image=login_logo_image, text="")
login_logo_label.pack(pady=(30, 10))

# Welcome label
login_welcome_label = ctk.CTkLabel(login_frame, text="Welcome to OkeyDokey!", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"), text_color="black")
login_welcome_label.pack(pady=(0, 20))

# Username and password entries
login_user_entry = ctk.CTkEntry(login_frame, placeholder_text="Username", placeholder_text_color="black", text_color="black", fg_color="#f0f0f0")
login_user_entry.pack(pady=8, ipadx=4, ipady=4)

login_pass_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
login_pass_frame.pack(pady=8)
login_pass_entry = ctk.CTkEntry(login_pass_frame, placeholder_text="Password", show="*", width=170, placeholder_text_color="black", text_color="black", fg_color="#f0f0f0", border_width=1, corner_radius=6)
login_pass_entry.pack(side="left", ipadx=4, ipady=4)
login_pw_visible = [False]

def toggle_login_pw():
    if login_pw_visible[0]:
        login_pass_entry.configure(show="*")
        login_eye_btn.configure(text="👁️")
    else:
        login_pass_entry.configure(show="")
        login_eye_btn.configure(text="👁")
    login_pw_visible[0] = not login_pw_visible[0]

login_eye_btn = ctk.CTkButton(
    login_pass_frame, text="👁️", width=32, height=32, fg_color="#f0f0f0", hover_color="#e0e0e0", border_width=0, corner_radius=6, command=toggle_login_pw)
login_eye_btn.pack(side="left", padx=0)

login_error = ctk.CTkLabel(login_frame, text="", text_color="black")
login_error.pack(pady=(0, 5))

# Login button
login_button = ctk.CTkButton(login_frame, text="LOGIN", width=220, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), command=check_login, text_color="white")
login_button.pack(pady=(18, 8))

# Don't have account button
register_link = ctk.CTkButton(login_frame, text="DON'T HAVE ACCOUNT?", width=220, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), command=show_register, text_color="white")
register_link.pack(pady=(15, 10))


# ---------- REGISTER PAGE ---------- #
for widget in register_frame.winfo_children():
    widget.destroy()

# Logo at the top
register_logo_image = ctk.CTkImage(light_image=Image.open("Logo2.png"), size=(120, 90))
register_logo_label = ctk.CTkLabel(register_frame, image=register_logo_image, text="")
register_logo_label.pack(pady=(30, 10))

# Welcome label
register_welcome_label = ctk.CTkLabel(register_frame, text="Welcome to OkeyDokey!", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"), text_color="black")
register_welcome_label.pack(pady=(0, 20))

# Username, password, confirm password entries
reg_user_entry = ctk.CTkEntry(register_frame, placeholder_text="Username", placeholder_text_color="black", text_color="black", fg_color="#f0f0f0")
reg_user_entry.pack(pady=8, ipadx=4, ipady=4)

reg_pass_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
reg_pass_frame.pack(pady=0)
reg_pass_entry = ctk.CTkEntry(reg_pass_frame, placeholder_text="Password", show="*", width=170, placeholder_text_color="black", text_color="black", fg_color="#f0f0f0", border_width=1, corner_radius=6)
reg_pass_entry.pack(side="left", pady=8, ipadx=4, ipady=4)
reg_pw_visible = [False]

def toggle_reg_pw():
    if reg_pw_visible[0]:
        reg_pass_entry.configure(show="*")
        reg_eye_btn.configure(text="👁️")
    else:
        reg_pass_entry.configure(show="")
        reg_eye_btn.configure(text="👁")
    reg_pw_visible[0] = not reg_pw_visible[0]

reg_eye_btn = ctk.CTkButton(
    reg_pass_frame, text="👁️", width=32, height=32, fg_color="#f0f0f0", hover_color="#e0e0e0", border_width=0, corner_radius=6, command=toggle_reg_pw)
reg_eye_btn.pack(side="left", padx=0)

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    while True:
        password = ''.join(random.choice(chars) for _ in range(length))
        # Ensure it meets all requirements
        if (any(c.isupper() for c in password) and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
            return password

def fill_generated_password():
    pw = generate_password()
    reg_pass_entry.delete(0, ctk.END)
    reg_pass_entry.insert(0, pw)
    reg_confirm_entry.delete(0, ctk.END)
    reg_confirm_entry.insert(0, pw)
    update_password_requirements()

gen_pw_btn = ctk.CTkButton(reg_pass_frame, text="Generate", width=90, command=fill_generated_password)
gen_pw_btn.pack(side="left", padx=6)

# Password requirement labels
req_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
req_frame.pack(pady=(0, 8))

length_req = ctk.CTkLabel(req_frame, text="• 6-20 characters", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
length_req.pack(anchor="w", pady=1)

upper_req = ctk.CTkLabel(req_frame, text="• One uppercase letter", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
upper_req.pack(anchor="w", pady=1)

number_req = ctk.CTkLabel(req_frame, text="• One number", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
number_req.pack(anchor="w", pady=1)

special_req = ctk.CTkLabel(req_frame, text="• One special character (!@#$%^&*()_+-=[]{}|;:,.<>?)", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
special_req.pack(anchor="w", pady=1)

def update_password_requirements(event=None):
    password = reg_pass_entry.get()
    unmet = 0
    # Update length requirement
    if 6 <= len(password) <= 20:
        length_req.pack_forget()
    else:
        length_req.pack(anchor="w", pady=1)
        unmet += 1
    # Update uppercase requirement
    if any(c.isupper() for c in password):
        upper_req.pack_forget()
    else:
        upper_req.pack(anchor="w", pady=1)
        unmet += 1
    # Update number requirement
    if any(c.isdigit() for c in password):
        number_req.pack_forget()
    else:
        number_req.pack(anchor="w", pady=1)
        unmet += 1
    # Update special character requirement
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        special_req.pack_forget()
    else:
        special_req.pack(anchor="w", pady=1)
        unmet += 1
    # Hide or show the requirements frame in the correct place
    if unmet == 0:
        req_frame.pack_forget()
    else:
        if not req_frame.winfo_ismapped():
            req_frame.pack(pady=(0, 8), before=reg_confirm_entry)

# Bind the password entry to update requirements
reg_pass_entry.bind('<KeyRelease>', update_password_requirements)

reg_confirm_entry = ctk.CTkEntry(register_frame, placeholder_text="Confirm Password", show="*", placeholder_text_color="black", text_color="black", fg_color="#f0f0f0")
reg_confirm_entry.pack(pady=8, ipadx=4, ipady=4)

reg_error = ctk.CTkLabel(register_frame, text="", text_color="red")
reg_error.pack(pady=(0, 5))

# Sign up button
reg_button = ctk.CTkButton(register_frame, text="SIGN UP", width=220, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), command=register_user, text_color="white")
reg_button.pack(pady=(18, 8))

# Back to login button
back_login_btn = ctk.CTkButton(register_frame, text="BACK TO LOGIN", width=220, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), command=back_to_login, text_color="white")
back_login_btn.pack(pady=(15, 10))


# ---------- MAIN PAGE (Screenshot Style) --- #
# Centered logo at the top
logo_row = ctk.CTkFrame(main_frame, fg_color="transparent")
logo_row.pack(pady=(18, 8))
logo_img = ctk.CTkImage(light_image=Image.open("Logo2.png"), size=(180, 60))
logo_label = ctk.CTkLabel(logo_row, image=logo_img, text="")
logo_label.pack()

# Filter and Add Password row
filter_row = ctk.CTkFrame(main_frame, fg_color="transparent")
filter_row.pack(fill="x", padx=18, pady=(0, 18))

# Center container for both elements
center_container = ctk.CTkFrame(filter_row, fg_color="transparent")
center_container.pack(expand=True)

vault_filter = ctk.CTkOptionMenu(
    center_container,
    values=["All Vaults", "Login", "Credit Card", "Notes"],
    width=200,
    height=35,
    fg_color="white",
    button_color="white",
    button_hover_color="#f0f0f0",
    text_color="black",
    dropdown_fg_color="white",
    dropdown_hover_color="#f0f0f0",
    dropdown_text_color="black"
)
vault_filter.set("All Vaults")
vault_filter.pack(side="left", padx=(0, 10))

add_pass_btn = ctk.CTkButton(
    center_container,
    text="+ Add Password",
    width=140,
    height=36,
    fg_color="#ffd6ec",
    text_color="#222",
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"),
    corner_radius=18,
    command=show_add_password
)
add_pass_btn.pack(side="left")

# Container for credentials
credentials_container = ctk.CTkFrame(main_frame, fg_color="transparent")
credentials_container.pack(fill="both", expand=True, padx=18, pady=(0, 18))

# Blue icons (use images for all categories)
asterisk_icon = ctk.CTkImage(light_image=Image.open("icon1.png"), size=(40, 40))
card_icon = ctk.CTkImage(light_image=Image.open("icon2.png"), size=(45, 40))
note_icon = ctk.CTkImage(light_image=Image.open("icon3.png"), size=(40, 40))

# Update credential cards

def refresh_main_credentials():
    for widget in credentials_container.winfo_children():
        widget.destroy()
    username = CURRENT_USER[0]
    files = get_user_files(username)
    if not os.path.exists(files['CREDENTIALS_FILE']):
        no_label = ctk.CTkLabel(credentials_container, text="No credentials found.", text_color="gray", fg_color="transparent")
        no_label.pack(pady=10)
        return
    with open(files['CREDENTIALS_FILE'], "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        no_label = ctk.CTkLabel(credentials_container, text="No saved credentials.", text_color="gray", fg_color="transparent")
        no_label.pack(pady=10)
        return
    selected_category = vault_filter.get()
    for idx, line in enumerate(lines):
        parts = line.split("|")
        if len(parts) < 2:
            continue
        category = parts[0]
        if selected_category != "All Vaults" and selected_category != category:
            continue
        # Card style: white, rounded, border
        card = ctk.CTkFrame(credentials_container, fg_color="white", corner_radius=14, border_width=2, border_color="#bbb")
        card.pack(fill="x", pady=8, padx=2)
        card.pack_propagate(False)
        card.configure(height=70)
        # Info text and icon
        if category == "Login":
            entry_type, email, _ = parts[1:]
            title = entry_type
            subtitle = email
            icon = asterisk_icon
        elif category == "Credit Card":
            card_name, card_number, card_expiry, enc_cvv = parts[1:]
            title = card_name
            subtitle = card_number
            icon = card_icon
        elif category == "Notes":
            title, enc_content = parts[1:]
            subtitle = "Hidden Note"
            icon = note_icon
        else:
            title = category
            subtitle = ""
            icon = ""
        # Layout: left info, right icon
        left = ctk.CTkFrame(card, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=16, pady=8)
        title_label = ctk.CTkLabel(left, text=title, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), text_color="#111")
        title_label.pack(anchor="w")
        subtitle_label = ctk.CTkLabel(left, text=subtitle, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=13), text_color="#444")
        subtitle_label.pack(anchor="w")
        icon_label = ctk.CTkLabel(card, image=icon, text="", fg_color="transparent")
        icon_label.pack(side="right", padx=18)
        # Make the whole card clickable
        card.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        left.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        title_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        subtitle_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        icon_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))

# Update vault filter to refresh on change
vault_filter.configure(command=lambda x: refresh_main_credentials())

# Logout button at bottom right
logout_btn_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
logout_btn_frame.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-10)
logout_btn = ctk.CTkButton(logout_btn_frame, text="➡️", width=48, height=48, fg_color="#f0f0f0", text_color="#222", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=28), corner_radius=24, command=logout)
logout_btn.pack()

# Call this after login or when returning to main page
def show_main():
    login_frame.pack_forget()
    register_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    main_frame.pack(fill="both", expand=True, padx=0, pady=0)
    refresh_main_credentials()

# ---------- ADD PASSWORD PAGE ---------- #
add_label = ctk.CTkLabel(add_frame, text="➕ Add New Credential", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold"))
add_label.pack(pady=10)

fields_frame = ctk.CTkFrame(add_frame)
fields_frame.pack(pady=10, fill="both", expand=True)

# Login fields
login_fields = ctk.CTkFrame(fields_frame)
type_entry = ctk.CTkEntry(login_fields, placeholder_text="Type (e.g., Gmail, Netflix)", fg_color="#f0f0f0")
type_entry.pack(pady=5)
email_entry = ctk.CTkEntry(login_fields, placeholder_text="Email/Username", fg_color="#f0f0f0")
email_entry.pack(pady=5)
password_entry = ctk.CTkEntry(login_fields, placeholder_text="Password", show="*", fg_color="#f0f0f0")
password_entry.pack(pady=5)

# Credit Card fields
card_fields = ctk.CTkFrame(fields_frame)
card_name_entry = ctk.CTkEntry(card_fields, placeholder_text="Name on Card", fg_color="#f0f0f0")
card_name_entry.pack(pady=5)
card_number_entry = ctk.CTkEntry(card_fields, placeholder_text="Card Number", fg_color="#f0f0f0")
card_number_entry.pack(pady=5)
card_expiry_entry = ctk.CTkEntry(card_fields, placeholder_text="Expiry Date (MM/YY)", fg_color="#f0f0f0")
card_expiry_entry.pack(pady=5)
card_cvv_entry = ctk.CTkEntry(card_fields, placeholder_text="CVV", show="*", fg_color="#f0f0f0")
card_cvv_entry.pack(pady=5)
# Add card type label and error label for add mode
add_card_number_label = ctk.CTkLabel(card_fields, text="")
add_card_number_label.pack(pady=5)
add_card_error_label = ctk.CTkLabel(card_fields, text="", text_color="red")
add_card_error_label.pack(pady=2)

def update_add_card_type(event=None):
    number = card_number_entry.get()
    if number.startswith("4"):
        add_card_number_label.configure(text="Visa")
    elif number.startswith("5") or number.startswith("2"):
        add_card_number_label.configure(text="Mastercard")
    elif number:
        add_card_number_label.configure(text="Unknown")
    else:
        add_card_number_label.configure(text="")
card_number_entry.bind('<KeyRelease>', update_add_card_type)

# Notes fields
notes_fields = ctk.CTkFrame(fields_frame)
notes_title_entry = ctk.CTkEntry(notes_fields, placeholder_text="Title", fg_color="#f0f0f0")
notes_title_entry.pack(pady=5)
notes_content = ctk.CTkTextbox(notes_fields, width=400, height=200, fg_color="#f0f0f0")
notes_content.pack(pady=5)

def switch_category_fields(choice):
    login_fields.pack_forget()
    card_fields.pack_forget()
    notes_fields.pack_forget()
    if choice == "Login":
        login_fields.pack(fill="both", expand=True)
    elif choice == "Credit Card":
        card_fields.pack(fill="both", expand=True)
    elif choice == "Notes":
        notes_fields.pack(fill="both", expand=True)

category_entry = ctk.CTkOptionMenu(
    add_frame,
    values=["Login", "Credit Card", "Notes"],
    command=switch_category_fields,
    width=260,
    height=35,
    fg_color="white",
    button_color="white",
    button_hover_color="#f0f0f0",
    text_color="black",
    dropdown_fg_color="white",
    dropdown_hover_color="#f0f0f0",
    dropdown_text_color="black"
)
category_entry.set("Login")
category_entry.pack(pady=5)

save_btn = ctk.CTkButton(add_frame, text="Save", command=save_credentials, text_color="white")
save_btn.pack(pady=10)

back_btn = ctk.CTkButton(add_frame, text="Back", command=show_main, text_color="white")
back_btn.pack(pady=5)


# ---------- VIEW PASSWORD PAGE ---------- #
view_label = ctk.CTkLabel(view_frame, text="📄 Saved Credentials", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold"))
view_label.pack(pady=10)

# Add category filter
category_filter_label = ctk.CTkLabel(view_frame, text="Filter by Category:")
category_filter_label.pack(pady=5)
category_filter = ctk.CTkOptionMenu(
    view_frame,
    values=["All", "Login", "Credit Card", "Notes"],
    command=lambda x: load_credentials(),
    width=260,
    height=35,
    fg_color="white",
    button_color="white",
    button_hover_color="#f0f0f0",
    text_color="black",
    dropdown_fg_color="white",
    dropdown_hover_color="#f0f0f0",
    dropdown_text_color="black"
)
category_filter.set("All")
category_filter.pack(pady=5)

textbox = ctk.CTkTextbox(view_frame, width=500, height=350, wrap="word", state="disabled")
textbox.pack(pady=10)

back_view_btn = ctk.CTkButton(view_frame, text="Back", command=show_main, text_color="white")
back_view_btn.pack(pady=5)


# ---------- EDIT PASSWORD PAGE ---------- #
edit_label = ctk.CTkLabel(edit_frame, text="✏️ Edit Credentials", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold"))
edit_label.pack(pady=10)

# Add category filter
edit_category_filter_label = ctk.CTkLabel(edit_frame, text="Filter by Category:")
edit_category_filter_label.pack(pady=5)
edit_category_filter = ctk.CTkOptionMenu(
    edit_frame,
    values=["All", "Login", "Credit Card", "Notes"],
    command=lambda x: load_credentials_listbox(),
    width=260,
    height=35,
    fg_color="white",
    button_color="white",
    button_hover_color="#f0f0f0",
    text_color="black",
    dropdown_fg_color="white",
    dropdown_hover_color="#f0f0f0",
    dropdown_text_color="black"
)
edit_category_filter.set("All")
edit_category_filter.pack(pady=5)

listbox_frame = ctk.CTkFrame(edit_frame)
listbox_frame.pack(pady=10, fill="both", expand=True)

scrollbar = Scrollbar(listbox_frame)
scrollbar.pack(side="right", fill="y")

listbox = Listbox(listbox_frame, yscrollcommand=scrollbar.set, width=60, height=15, font=("Courier", 12))
listbox.pack(side="left", fill="both", expand=True)

scrollbar.config(command=listbox.yview)

edit_button = ctk.CTkButton(edit_frame, text="Edit Selected", command=edit_selected, text_color="white")
edit_button.pack(pady=5)

delete_button = ctk.CTkButton(edit_frame, text="Delete Selected", command=delete_selected, text_color="white")
delete_button.pack(pady=5)

back_edit_btn = ctk.CTkButton(edit_frame, text="Back", command=show_main, text_color="white")
back_edit_btn.pack(pady=5)


# ---------- START THE APP ---------- #
# Define show_login before using it in the button

def show_login():
    opening_frame.pack_forget()
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Set white background for opening_frame
opening_frame.configure(fg_color="white")

# Use grid for better layout control
opening_frame.grid_rowconfigure(0, weight=1)
opening_frame.grid_rowconfigure(1, weight=0)
opening_frame.grid_rowconfigure(2, weight=1)
opening_frame.grid_columnconfigure(0, weight=1)

# Load and display the logo image (centered)
logo_image = ctk.CTkImage(light_image=Image.open("Logo.png"), size=(400, 220))
logo_label = ctk.CTkLabel(opening_frame, image=logo_image, text="")
logo_label.grid(row=1, column=0, pady=(0, 0), sticky="n")

# "Get Started!" button near the bottom
get_started_btn = ctk.CTkButton(opening_frame, text="Get Started!", width=200, height=40, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=18, weight="bold"), command=lambda: show_login(), text_color="white")
get_started_btn.grid(row=2, column=0, pady=(30, 40), sticky="s")

# Show the opening frame
opening_frame.pack(fill="both", expand=True, padx=20, pady=20)

# ---------- CREDENTIAL DETAILS PAGE (as a full page) ---------- #
details_frame = ctk.CTkFrame(app, fg_color="black")

show_pw_var = ctk.BooleanVar(value=False)

pw_toggle = ctk.CTkSwitch(details_frame, text="Show Passwords", variable=show_pw_var)
pw_toggle.pack(pady=(10, 0))

details_title = ctk.CTkLabel(details_frame, text="🔍 Credential Details", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold"), text_color="white")
details_title.pack(pady=(10, 10))

details_text = ctk.CTkTextbox(details_frame, width=480, height=220, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=14), fg_color="#222", text_color="white")
details_text.pack(pady=8)
details_text.configure(state="disabled")

# Button row
btn_row = ctk.CTkFrame(details_frame, fg_color="transparent")
btn_row.pack(pady=(10, 0))

edit_btn = ctk.CTkButton(btn_row, text="🖉  Edit", width=120)
edit_btn.pack(side="left", padx=8)
delete_btn = ctk.CTkButton(btn_row, text="🗑️  Delete", width=120, fg_color="#d32f2f")
delete_btn.pack(side="left", padx=8)

back_btn = ctk.CTkButton(details_frame, text="Back", width=260)
back_btn.pack(pady=(18, 0))

# Show/hide password logic
current_cred = {'parts': None, 'category': None, 'idx': None, 'lines': None}
def update_details_text():
    details_text.configure(state="normal")
    details_text.delete("1.0", ctk.END)
    parts = current_cred['parts']
    category = current_cred['category']
    username = CURRENT_USER[0]
    show_pw = show_pw_var.get()
    if category == "Login":
        entry_type, email, enc_password = parts[1:]
        try:
            password = decrypt_data(enc_password, username) if show_pw else "*****"
        except:
            password = "[Error decrypting]"
        details = f"Category: Login\nType: {entry_type}\nEmail: {email}\nPassword: {password}"
    elif category == "Credit Card":
        card_name, card_number, card_expiry, enc_cvv = parts[1:]
        try:
            cvv = decrypt_data(enc_cvv, username) if show_pw else "*****"
        except:
            cvv = "[Error decrypting]"
        details = f"Category: Credit Card\nName: {card_name}\nNumber: {card_number}\nExpiry: {card_expiry}\nCVV: {cvv}"
    elif category == "Notes":
        title, enc_content = parts[1:]
        try:
            content = decrypt_data(enc_content, username) if show_pw else "*****"
        except:
            content = "[Error decrypting]"
        details = f"Category: Notes\nTitle: {title}\nContent: {content}"
    else:
        details = "Unknown format"
    details_text.insert("1.0", details)
    details_text.configure(state="disabled")

pw_toggle.configure(command=update_details_text)

# Edit and delete button logic
def show_credential_details(idx, parts, category, lines):
    current_cred['parts'] = parts
    current_cred['category'] = category
    current_cred['idx'] = idx
    current_cred['lines'] = lines
    update_details_text()
    def edit_action():
        details_frame.pack_forget()
        original_line = "|".join(parts)
        edit_credential_in_page(parts, original_line)
    def delete_action():
        del lines[idx]
        files = get_user_files(CURRENT_USER[0])
        with open(files['CREDENTIALS_FILE'], "w") as f:
            for l in lines:
                f.write(l+"\n")
        details_frame.pack_forget()
        show_main()
    def back_action():
        details_frame.pack_forget()
        show_main()
    edit_btn.configure(command=edit_action)
    delete_btn.configure(command=delete_action)
    back_btn.configure(command=back_action)
    main_frame.pack_forget()
    details_frame.pack(fill="both", expand=True)

# --- Move edit_credential_in_page and update_credential_line above show_credential_details --- #
def update_credential_line(old_line, new_line):
    username = CURRENT_USER[0]
    files = get_user_files(username)
    with open(files['CREDENTIALS_FILE'], 'r') as f:
        lines = [line.strip() for line in f if line.strip()]
    with open(files['CREDENTIALS_FILE'], 'w') as f:
        for line in lines:
            if line == old_line:
                f.write(new_line + "\n")
            else:
                f.write(line + "\n")

def edit_credential_in_page(parts, original_line):
    username = CURRENT_USER[0]
    files = get_user_files(username)
    category = parts[0]
    selected_line = original_line

    # Switch to the add_frame for editing
    main_frame.pack_forget()
    view_frame.pack_forget()
    add_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Set category and show relevant fields
    category_entry.set(category)
    switch_category_fields(category)

    # Pre-fill fields
    if category == "Login":
        entry_type, email, enc_password = parts[1:4]
        password = decrypt_data(enc_password, username)
        type_entry.delete(0, ctk.END)
        type_entry.insert(0, entry_type)
        email_entry.delete(0, ctk.END)
        email_entry.insert(0, email)
        password_entry.delete(0, ctk.END)
        password_entry.insert(0, password)

    elif category == "Credit Card":
        name, number, expiry, enc_cvv = parts[1:5]
        cvv = decrypt_data(enc_cvv, username)
        card_name_entry.delete(0, ctk.END)
        card_name_entry.insert(0, name)
        card_number_entry.delete(0, ctk.END)
        card_number_entry.insert(0, number)
        card_expiry_entry.delete(0, ctk.END)
        card_expiry_entry.insert(0, expiry)
        card_cvv_entry.delete(0, ctk.END)
        card_cvv_entry.insert(0, cvv)
        # Add card type label
        global card_number_label
        card_number_label = ctk.CTkLabel(add_frame, text="")
        card_number_label.pack(pady=5)
        # Add error label (below card type label)
        global card_error_label
        card_error_label = ctk.CTkLabel(add_frame, text="", text_color="red")
        card_error_label.pack(pady=2)
        # Set initial card type
        if number.startswith("4"):
            card_number_label.configure(text="Visa")
        elif number.startswith("5") or number.startswith("2"):
            card_number_label.configure(text="Mastercard")
        else:
            card_number_label.configure(text="Unknown")

    elif category == "Notes":
        title, enc_content = parts[1:3]
        content = decrypt_data(enc_content, username)
        notes_title_entry.delete(0, ctk.END)
        notes_title_entry.insert(0, title)
        notes_content.delete("1.0", ctk.END)
        notes_content.insert("1.0", content)

    # Update function
    def update_changes():
        if category == "Login":
            new_type = type_entry.get().strip()
            new_email = email_entry.get().strip()
            new_password = password_entry.get().strip()
            if not all([new_type, new_email, new_password]):
                messagebox.showwarning("Incomplete", "All fields are required.")
                return
            encrypted = encrypt_data(new_password, username)
            new_line = f"Login|{new_type}|{new_email}|{encrypted}"

        elif category == "Credit Card":
            new_name = card_name_entry.get().strip()
            new_number = card_number_entry.get().strip()
            new_expiry = card_expiry_entry.get().strip()
            new_cvv = card_cvv_entry.get().strip()

            # Reset error and label
            card_error_label.configure(text="")
            card_number_label.configure(text="")

            if not all([new_name, new_number, new_expiry, new_cvv]):
                card_error_label.configure(text="Please fill in all card fields.")
                return

            # Validation
            import re
            if not re.match(r"^\d{4}-\d{4}-\d{4}-\d{4}$", new_number):
                card_error_label.configure(text="Invalid Card Details")
                return

            if not (new_number.startswith("4") or new_number.startswith("5") or new_number.startswith("2")):
                card_error_label.configure(text="Invalid Card Details")
                return

            if not re.match(r"^(0[1-9]|1[0-2])/\d{2}$", new_expiry):
                card_error_label.configure(text="Invalid Card Details")
                return

            if not re.match(r"^\d{3}$", new_cvv):
                card_error_label.configure(text="Invalid Card Details")
                return

            # Determine card type
            if new_number.startswith("4"):
                card_number_label.configure(text="Visa")
            elif new_number.startswith("5") or new_number.startswith("2"):
                card_number_label.configure(text="Mastercard")
            else:
                card_number_label.configure(text="Unknown")

            encrypted = encrypt_data(new_cvv, username)
            new_line = f"Credit Card|{new_name}|{new_number}|{new_expiry}|{encrypted}"

        elif category == "Notes":
            new_title = notes_title_entry.get().strip()
            new_content = notes_content.get("1.0", ctk.END).strip()
            if not all([new_title, new_content]):
                messagebox.showwarning("Incomplete", "All fields are required.")
                return
            encrypted = encrypt_data(new_content, username)
            new_line = f"Notes|{new_title}|{encrypted}"

        update_credential_line(selected_line, new_line)
        messagebox.showinfo("Success", "Credential updated.")
        show_main()

    # Reconfigure buttons for update mode
    save_btn.configure(text="Update", command=update_changes)
    back_btn.configure(text="Cancel", command=show_main)

app.mainloop()
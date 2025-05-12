# IMPORTS
import customtkinter as ctk
import os
import base64
import hashlib
from tkinter import messagebox, Listbox, Scrollbar
from cryptography.fernet import Fernet


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
    CURRENT_USER[0] = None
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
                        show_mfa_verify_prompt(username, after_mfa)
                    else:
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
        
        # Create user-specific files
        files = get_user_files(username)
        open(files['CREDENTIALS_FILE'], 'w').close()  # Create empty credentials file
        generate_key(username)  # Generate encryption key for the user
        
        # Save user credentials
        with open(USER_CREDENTIALS_FILE, "a") as f:
            f.write(f"{username},{password}\n")
        
        CURRENT_USER[0] = username
        show_mfa_prompt(username)

def show_mfa_prompt(username):
    mfa_window = ctk.CTkToplevel(app)
    mfa_window.title("Set MFA Question")
    mfa_window.geometry("400x250")

    label = ctk.CTkLabel(mfa_window, text="Set a security question for MFA:")
    label.pack(pady=10)
    question_entry = ctk.CTkEntry(mfa_window, placeholder_text="Enter your question")
    question_entry.pack(pady=10)
    answer_label = ctk.CTkLabel(mfa_window, text="Answer:")
    answer_label.pack(pady=5)
    answer_entry = ctk.CTkEntry(mfa_window, placeholder_text="Enter your answer")
    answer_entry.pack(pady=10)

    def save_mfa():
        question = question_entry.get().strip()
        answer = answer_entry.get().strip()
        if not question or not answer:
            label.configure(text="Both fields are required!", text_color="red")
            return
        files = get_user_files(username)
        mfa_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_mfa.txt')
        with open(mfa_file, 'w') as f:
            f.write(question + '\n')
            f.write(answer + '\n')  # Store as plain text
        mfa_window.destroy()
        messagebox.showinfo("Success", "MFA question set!")
        back_to_login()

    save_btn = ctk.CTkButton(mfa_window, text="Save", command=save_mfa)
    save_btn.pack(pady=10)

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
            name_entry = ctk.CTkEntry(edit_window)
            name_entry.insert(0, card_name)
            name_entry.pack(pady=5)

            number_label = ctk.CTkLabel(edit_window, text="Card Number:")
            number_label.pack(pady=5)
            number_entry = ctk.CTkEntry(edit_window)
            number_entry.insert(0, card_number)
            number_entry.pack(pady=5)

            expiry_label = ctk.CTkLabel(edit_window, text="Expiry Date:")
            expiry_label.pack(pady=5)
            expiry_entry = ctk.CTkEntry(edit_window)
            expiry_entry.insert(0, card_expiry)
            expiry_entry.pack(pady=5)

            cvv_label = ctk.CTkLabel(edit_window, text="CVV:")
            cvv_label.pack(pady=5)
            cvv_entry = ctk.CTkEntry(edit_window, show="*")
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
            title_entry = ctk.CTkEntry(edit_window)
            title_entry.insert(0, title)
            title_entry.pack(pady=5)

            content_label = ctk.CTkLabel(edit_window, text="Content:")
            content_label.pack(pady=5)
            content_entry = ctk.CTkTextbox(edit_window, width=300, height=150)
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

def show_mfa_verify_prompt(username, on_success):
    files = get_user_files(username)
    mfa_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_mfa.txt')
    if not os.path.exists(mfa_file):
        on_success()
        return
    with open(mfa_file, 'r') as f:
        question = f.readline().strip()
        correct_answer = f.readline().strip()

    mfa_window = ctk.CTkToplevel(app)
    mfa_window.title("MFA Verification")
    mfa_window.geometry("400x200")
    label = ctk.CTkLabel(mfa_window, text=question)
    label.pack(pady=10)
    answer_entry = ctk.CTkEntry(mfa_window, placeholder_text="Your answer")
    answer_entry.pack(pady=10)

    def check_answer():
        answer = answer_entry.get().strip()
        if answer.strip().lower() == correct_answer.strip().lower():
            mfa_window.destroy()
            on_success()
        else:
            label.configure(text="Incorrect answer. Try again.", text_color="red")

    submit_btn = ctk.CTkButton(mfa_window, text="Submit", command=check_answer)
    submit_btn.pack(pady=10)

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

fields_frame = ctk.CTkFrame(add_frame)
fields_frame.pack(pady=10, fill="both", expand=True)

# Login fields
login_fields = ctk.CTkFrame(fields_frame)
type_entry = ctk.CTkEntry(login_fields, placeholder_text="Type (e.g., Gmail, Netflix)")
type_entry.pack(pady=5)
email_entry = ctk.CTkEntry(login_fields, placeholder_text="Email/Username")
email_entry.pack(pady=5)
password_entry = ctk.CTkEntry(login_fields, placeholder_text="Password", show="*")
password_entry.pack(pady=5)

# Credit Card fields
card_fields = ctk.CTkFrame(fields_frame)
card_name_entry = ctk.CTkEntry(card_fields, placeholder_text="Name on Card")
card_name_entry.pack(pady=5)
card_number_entry = ctk.CTkEntry(card_fields, placeholder_text="Card Number")
card_number_entry.pack(pady=5)
card_expiry_entry = ctk.CTkEntry(card_fields, placeholder_text="Expiry Date (MM/YY)")
card_expiry_entry.pack(pady=5)
card_cvv_entry = ctk.CTkEntry(card_fields, placeholder_text="CVV", show="*")
card_cvv_entry.pack(pady=5)

# Notes fields
notes_fields = ctk.CTkFrame(fields_frame)
notes_title_entry = ctk.CTkEntry(notes_fields, placeholder_text="Title")
notes_title_entry.pack(pady=5)
notes_content = ctk.CTkTextbox(notes_fields, width=400, height=200)
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
    command=switch_category_fields
)
category_entry.set("Login")
category_entry.pack(pady=5)

save_btn = ctk.CTkButton(add_frame, text="Save", command=save_credentials)
save_btn.pack(pady=10)

back_btn = ctk.CTkButton(add_frame, text="Back", command=show_main)
back_btn.pack(pady=5)


# ---------- VIEW PASSWORD PAGE ---------- #
view_label = ctk.CTkLabel(view_frame, text="📄 Saved Credentials", font=ctk.CTkFont(size=24, weight="bold"))
view_label.pack(pady=10)

# Add category filter
category_filter_label = ctk.CTkLabel(view_frame, text="Filter by Category:")
category_filter_label.pack(pady=5)
category_filter = ctk.CTkOptionMenu(view_frame, values=["All", "Login", "Credit Card", "Notes"], command=lambda x: load_credentials())
category_filter.set("All")
category_filter.pack(pady=5)

textbox = ctk.CTkTextbox(view_frame, width=500, height=350, wrap="word", state="disabled")
textbox.pack(pady=10)

back_view_btn = ctk.CTkButton(view_frame, text="Back", command=show_main)
back_view_btn.pack(pady=5)


# ---------- EDIT PASSWORD PAGE ---------- #
edit_label = ctk.CTkLabel(edit_frame, text="✏️ Edit Credentials", font=ctk.CTkFont(size=24, weight="bold"))
edit_label.pack(pady=10)

# Add category filter
edit_category_filter_label = ctk.CTkLabel(edit_frame, text="Filter by Category:")
edit_category_filter_label.pack(pady=5)
edit_category_filter = ctk.CTkOptionMenu(edit_frame, values=["All", "Login", "Credit Card", "Notes"], command=lambda x: load_credentials_listbox())
edit_category_filter.set("All")
edit_category_filter.pack(pady=5)

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
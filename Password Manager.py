import customtkinter as ctk
import os

# Configure CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# Files
CREDENTIALS_FILE = "savedcredentials.txt"
USER_CREDENTIALS_FILE = "user_credentials.txt"

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

# ---------- PAGE SWITCHING ---------- #
def show_main():
    login_frame.pack_forget()
    register_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
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

# ---------- NEWWWWWWW ---------- #
def logout():
    main_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    login_user_entry.delete(0, ctk.END)
    login_pass_entry.delete(0, ctk.END)
    login_error.configure(text="")  # Also clears any old error message
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
        with open(CREDENTIALS_FILE, "a") as f:
            f.write(f"{entry_type},{entry_email},{entry_password}\n")
        clear_inputs()

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
                    entry_type, email, password = parts
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
main_label = ctk.CTkLabel(main_frame, text="Password Manager", font=ctk.CTkFont(size=32, weight="bold"))
main_label.pack(pady=40)

add_btn = ctk.CTkButton(main_frame, text="Add Password", command=show_add_password, width=200)
add_btn.pack(pady=10)

view_btn = ctk.CTkButton(main_frame, text="View Password", command=show_view_passwords, width=200)
view_btn.pack(pady=10)

# ---------- NEWWWWWWW ---------- #
logout_btn = ctk.CTkButton(main_frame, text="Logout", command=logout, width=200)
logout_btn.pack(pady=10)

# ---------- ADD PASSWORD PAGE ---------- #
header_label = ctk.CTkLabel(add_frame, text="➕ ADD", font=ctk.CTkFont(size=32, weight="bold"), text_color="#FF66CC")
header_label.pack(pady=(10, 20))

type_label = ctk.CTkLabel(add_frame, text="1] Type:", text_color="#B266FF", anchor="w")
type_label.pack(fill="x")
type_entry = ctk.CTkEntry(add_frame, placeholder_text="e.g., Facebook")
type_entry.pack(pady=5)

email_label = ctk.CTkLabel(add_frame, text="2] Email:", text_color="#B266FF", anchor="w")
email_label.pack(fill="x")
email_entry = ctk.CTkEntry(add_frame, placeholder_text="example@gmail.com")
email_entry.pack(pady=5)

password_label = ctk.CTkLabel(add_frame, text="3] Password:", text_color="#B266FF", anchor="w")
password_label.pack(fill="x")
password_entry = ctk.CTkEntry(add_frame, show="", placeholder_text="**********")
password_entry.pack(pady=5)

button_frame = ctk.CTkFrame(add_frame, fg_color="transparent")
button_frame.pack(pady=20)

save_btn = ctk.CTkButton(button_frame, text="Save", width=100, command=save_credentials)
save_btn.grid(row=0, column=0, padx=5)

clear_btn = ctk.CTkButton(button_frame, text="All Clear", width=100, command=clear_inputs)
clear_btn.grid(row=0, column=1, padx=5)

back_btn = ctk.CTkButton(button_frame, text="Back", width=100, command=show_main)
back_btn.grid(row=0, column=2, padx=5)

# ---------- VIEW PASSWORD PAGE ---------- #
view_label = ctk.CTkLabel(view_frame, text="Saved Credentials", font=ctk.CTkFont(size=28, weight="bold"), text_color="#66CCFF")
view_label.pack(pady=(10, 10))

textbox = ctk.CTkTextbox(view_frame, width=500, height=350, font=ctk.CTkFont(size=14))
textbox.pack(pady=10)
textbox.configure(state="disabled")

back_view_btn = ctk.CTkButton(view_frame, text="Back", command=show_main)
back_view_btn.pack(pady=10)

# ---------- STARTUP ---------- #
login_frame.pack(fill="both", expand=True, padx=20, pady=20)
app.mainloop()
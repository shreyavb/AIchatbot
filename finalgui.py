import tkinter as tk
from tkinter import messagebox, Toplevel, scrolledtext
import csv
import hashlib  # For password hashing
from tensorflow import keras
import numpy as np
import json
import pickle
import random  # For random choice

# Global variables to store user credentials
user_credentials_file = 'user_credentials.csv'

# Load the trained model
model = keras.models.load_model('chat-model.keras')

# Load tokenizer object
with open('tokenizer.pickle', 'rb') as handle:
    tokenizer = pickle.load(handle)

# Load label encoder object
with open('label_encoder.pickle', 'rb') as enc:
    lbl_encoder = pickle.load(enc)

# Load intents
with open('intents.json') as file:
    data = json.load(file)

# Define a function to get the response
def get_response(msg):
    max_len = 20
    result = model.predict(keras.preprocessing.sequence.pad_sequences(tokenizer.texts_to_sequences([msg]),
                                                                       truncating='post', maxlen=max_len))
    tag = lbl_encoder.inverse_transform([np.argmax(result)])

    for i in data['intents']:
        if i['tag'] == tag:
            return random.choice(i['responses'])  # Use random.choice for random selection
    return "I didn't understand that."

# Function to display messages in chat bubbles
def display_message(message, sender):
    chat_window.config(state=tk.NORMAL)
    
    # Determine bubble properties
    bubble_color = "#0084ff" if sender == "user" else "#e5e5ea"  # Blue for user, light gray for bot
    text_color = "#ffffff" if sender == "user" else "#000000"  # White text for user, black for bot
    bubble_align = "e" if sender == "user" else "w"  # Right for user, left for bot
    
    # Create the bubble frame
    bubble_frame = tk.Frame(chat_window, bg=bubble_color, padx=10, pady=5)
    bubble_frame.pack(anchor=bubble_align, pady=5, padx=10, fill=tk.X)
    
    # Create the bubble label
    bubble_label = tk.Label(bubble_frame, text=message, bg=bubble_color, fg=text_color,
                            font=("Arial", 12), wraplength=300, justify=tk.LEFT)
    bubble_label.pack(anchor=bubble_align, padx=5, pady=5)
    
    # Add the frame to the text window
    chat_window.window_create(tk.END, window=bubble_frame)
    chat_window.insert(tk.END, "\n")
    
    # Ensure the latest message is visible
    chat_window.see(tk.END)
    
    chat_window.config(state=tk.DISABLED)

# Function to send messages
def send():
    user_input = user_msg.get()
    if user_input.strip() == "":
        messagebox.showwarning("Empty Input", "Please enter a message.")
        return
    display_message(user_input, "user")
    user_msg.set('')
    response = get_response(user_input)
    display_message(response, "bot")

# Function to handle signup process
def signup():
    signup_window = Toplevel(app)
    signup_window.title("Signup")
    
    def save_credentials():
        email = email_entry.get()
        password = password_entry.get()
        
        if email == "" or password == "":
            messagebox.showwarning("Empty Fields", "Please fill in all fields.")
            return
        
        # Encrypt the password using MD5 hashing (not very secure, just for demonstration)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        # Save credentials to a CSV file
        with open(user_credentials_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([email, hashed_password])
        
        messagebox.showinfo("Signup Successful", "Signup successful. Please login.")
        signup_window.destroy()
        show_login()

    email_label = tk.Label(signup_window, text="Email:")
    email_label.pack()
    email_entry = tk.Entry(signup_window, width=30)
    email_entry.pack(pady=5)
    
    password_label = tk.Label(signup_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(signup_window, width=30, show="*")
    password_entry.pack(pady=5)
    
    signup_button = tk.Button(signup_window, text="Signup", command=save_credentials)
    signup_button.pack(pady=10)

# Function to handle login process
def login():
    login_window = Toplevel(app)
    login_window.title("Login")
    
    def check_credentials():
        email = email_entry.get()
        password = password_entry.get()
        
        if email == "" or password == "":
            messagebox.showwarning("Empty Fields", "Please fill in all fields.")
            return
        
        # Hash the password to match with stored credentials
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        # Check credentials from the CSV file
        with open(user_credentials_file, mode='r') as file:
            reader = csv.reader(file)
            for row in reader:
                if row[0] == email and row[1] == hashed_password:
                    messagebox.showinfo("Login Successful", "Login successful.")
                    login_window.destroy()
                    show_chat_interface()
                    return
            
        messagebox.showerror("Login Failed", "Invalid credentials. Please try again.")
    
    email_label = tk.Label(login_window, text="Email:")
    email_label.pack()
    email_entry = tk.Entry(login_window, width=30)
    email_entry.pack(pady=5)
    
    password_label = tk.Label(login_window, text="Password:")
    password_label.pack()
    password_entry = tk.Entry(login_window, width=30, show="*")
    password_entry.pack(pady=5)
    
    login_button = tk.Button(login_window, text="Login", command=check_credentials)
    login_button.pack(pady=10)

# Function to show main chat interface
def show_chat_interface():
    app.deiconify()

# Function to hide main chat interface
def hide_chat_interface():
    app.withdraw()

# Set up the main application window
app = tk.Tk()
app.title("Chatbot GUI")
app.geometry("400x600")
app.configure(bg="#f0f0f0")

# Create a startup window with options
startup_window = Toplevel(app)
startup_window.title("Welcome")
startup_window.geometry("300x200")

def use_as_guest():
    startup_window.destroy()
    show_chat_interface()

def show_signup():
    startup_window.destroy()
    signup()

def show_login():
    startup_window.destroy()
    login()

welcome_label = tk.Label(startup_window, text="Welcome to the Chatbot!")
welcome_label.pack(pady=20)

use_guest_button = tk.Button(startup_window, text="Use as Guest", command=use_as_guest)
use_guest_button.pack(pady=10)

signup_button = tk.Button(startup_window, text="Signup", command=show_signup)
signup_button.pack(pady=10)

login_button = tk.Button(startup_window, text="Login", command=show_login)
login_button.pack(pady=10)

# Hide the main chat interface initially
hide_chat_interface()

# Create a scrolled text widget for the chat window
chat_frame = tk.Frame(app, bg="#f0f0f0")
chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

chat_window = tk.Text(chat_frame, bg="#f0f0f0", bd=0, highlightthickness=0, wrap="word")
chat_window.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

scrollbar = tk.Scrollbar(chat_frame, orient=tk.VERTICAL, command=chat_window.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

chat_window.config(yscrollcommand=scrollbar.set)
chat_window.config(state=tk.DISABLED)

# Create a frame for the message input and send button
input_frame = tk.Frame(app, bg="#f0f0f0")
input_frame.pack(fill=tk.X, padx=10, pady=10)

user_msg = tk.StringVar()
user_entry = tk.Entry(input_frame, textvariable=user_msg, width=30, font=("Arial", 14), bd=2, relief=tk.GROOVE)
user_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

send_button = tk.Button(input_frame, text="Send", command=send, width=10, bg="#007acc", fg="#ffffff",
                        font=("Arial", 14, "bold"))
send_button.pack(side=tk.RIGHT)

# Run the application
app.mainloop()

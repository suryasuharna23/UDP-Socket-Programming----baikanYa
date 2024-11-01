import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Setup socket UDP
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_message():
    message = message_input.get()
    if message.strip().upper() == "EXIT":
        # Notify server and other clients that this user is leaving
        exit_message = f"{name} has left the chat."
        client.sendto(exit_message.encode(), (server_ip, server_port))
        
        # Display exit message locally and close the GUI
        chat_window.insert(tk.END, "Exiting chat...\n")
        chat_window.yview(tk.END)
        client.close()
        root.quit()  # Close GUI
    else:
        # Send normal message to server
        full_message = f'{name}: "{message}"'
        client.sendto(full_message.encode(), (server_ip, server_port))
        chat_window.insert(tk.END, f"{full_message}\n")
        chat_window.yview(tk.END)  # Scroll to the end
        message_input.delete(0, tk.END)

def receive():
    while True:
        try:
            message, _ = client.recvfrom(1024)
            decoded_message = message.decode()

            # If this client receives an exit notification, display it
            if decoded_message.endswith("has left the chat."):
                chat_window.insert(tk.END, f"{decoded_message}\n")
                chat_window.yview(tk.END)
            else:
                # Display other messages normally
                chat_window.insert(tk.END, f"{decoded_message}\n")
                chat_window.yview(tk.END)
        except Exception as e:
            chat_window.insert(tk.END, f"Error receiving message: {e}\n")
            break

    client.close()
    root.quit()  # Ensure GUI closes when the loop ends

def login():
    global server_ip, server_port, name
    server_ip = server_ip_input.get()
    server_port = int(server_port_input.get())
    name = nickname_input.get()
    password = password_input.get()

    if not server_ip or not server_port or not name or not password:
        messagebox.showwarning("Input Error", "All fields are required")
        return

    try:
        # Send login request to server
        client.sendto(f"SIGNUP_TAG:{name}:{password}".encode(), (server_ip, server_port))
        
        # Receive response from server
        response, _ = client.recvfrom(1024)
        response_decoded = response.decode()

        if response_decoded.startswith("Welcome"):
            chat_window.insert(tk.END, response_decoded + "\n")
            chat_window.yview(tk.END)
            login_frame.pack_forget()
            chat_frame.pack(fill="both", expand=True)

            threading.Thread(target=receive, daemon=True).start()

        else:
            messagebox.showwarning("Login Error", response_decoded)

    except Exception as e:
        messagebox.showerror("Connection Error", f"Unable to connect: {e}")
        return

# Setup GUI for login
root = tk.Tk()
root.title("Client Chat")
root.geometry("600x400")

login_frame = tk.Frame(root)
login_frame.pack(fill="both", expand=True)

chat_frame = tk.Frame(root)

server_ip_label = tk.Label(login_frame, text="Server IP:")
server_ip_label.pack(padx=10, pady=5)
server_ip_input = tk.Entry(login_frame)
server_ip_input.pack(padx=10, pady=5)

server_port_label = tk.Label(login_frame, text="Server Port:")
server_port_label.pack(padx=10, pady=5)
server_port_input = tk.Entry(login_frame)
server_port_input.pack(padx=10, pady=5)

nickname_label = tk.Label(login_frame, text="Nickname:")
nickname_label.pack(padx=10, pady=5)
nickname_input = tk.Entry(login_frame)
nickname_input.pack(padx=10, pady=5)

password_label = tk.Label(login_frame, text="Password:")
password_label.pack(padx=10, pady=5)
password_input = tk.Entry(login_frame, show="*")
password_input.pack(padx=10, pady=5)

login_button = tk.Button(login_frame, text="Login", command=login)
login_button.pack(padx=10, pady=20)

# Chat window setup
chat_window = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, width=70, height=15)
chat_window.pack(padx=10, pady=10)

message_input = tk.Entry(chat_frame)
message_input.pack(fill="x", padx=10, pady=10)
message_input.bind("<Return>", lambda event: send_message())

send_button = tk.Button(chat_frame, text="Send", command=send_message)
send_button.pack(padx=10, pady=10)

root.mainloop()

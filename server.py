import socket
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext, messagebox, font
import re  # For validating IP addresses

# Queue for storing messages
messages = queue.Queue()
clients = {}

# GUI setup
server_gui = tk.Tk()
server_gui.title("Server Chat")

# Set font styles
default_font = font.Font(family="Arial", size=12)
log_area = scrolledtext.ScrolledText(server_gui, wrap=tk.WORD, width=100, height=15, font=default_font)
log_area.pack(padx=10, pady=10)

# Entry for IP and port
ip_label = tk.Label(server_gui, text="Server IP (0.0.0.0 for all interfaces):")
ip_label.pack(padx=5, pady=5)
ip_entry = tk.Entry(server_gui)
ip_entry.pack(padx=5, pady=5)

port_label = tk.Label(server_gui, text="Server Port:")
port_label.pack(padx=5, pady=5)
port_entry = tk.Entry(server_gui)
port_entry.pack(padx=5, pady=5)

# Entry for Password
password_label = tk.Label(server_gui, text="Server Password:")
password_label.pack(padx=5, pady=5)
password_entry = tk.Entry(server_gui, show='*')
password_entry.pack(padx=5, pady=5)

server = None
is_server_running = False  # Flag to check server status
threads = []  # List of running threads

def validate_ip(ip):
    """Validate the IP address format."""
    pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return pattern.match(ip) is not None or ip == "0.0.0.0"

def validate_port(port):
    """Validate that the port is a valid number between 1024 and 65535."""
    return 1024 <= port <= 65535

def start_server():
    global server, is_server_running, threads

    if is_server_running:
        messagebox.showwarning("Warning", "Server is already running!")
        return

    server_ip = ip_entry.get()
    server_port = port_entry.get()
    PASSWORD = password_entry.get()

    # Validate input
    if not server_ip or not server_port or not PASSWORD:
        messagebox.showerror("Input Error", "All fields (IP, Port, Password) are required!")
        return

    if not validate_ip(server_ip):
        messagebox.showerror("Input Error", "Invalid IP address format! Use '0.0.0.0' to bind to all interfaces.")
        return

    if not server_port.isdigit() or not validate_port(int(server_port)):
        messagebox.showerror("Input Error", "Port must be a number between 1024 and 65535!")
        return

    try:
        server_port = int(server_port)
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((server_ip, server_port))  # Bind to the specified IP and port

        log_area.insert(tk.END, f"Server started on {server_ip}:{server_port}\n")
        log_area.insert(tk.END, "Waiting for clients to connect...\n")
        log_area.yview(tk.END)
        is_server_running = True

        def receive():
            while is_server_running:
                try:
                    message, addr = server.recvfrom(1024)
                    messages.put((message, addr))
                except Exception as e:
                    if is_server_running:
                        log_area.insert(tk.END, f"Error receiving message: {e}\n")
                        log_area.yview(tk.END)

        def broadcast():
            while is_server_running:
                while not messages.empty():
                    message, addr = messages.get()
                    message_decoded = message.decode()
                    log_area.insert(tk.END, f"Message from {clients.get(addr, addr)}: {message_decoded}\n")
                    log_area.yview(tk.END)

                    # Check if the client has logged in
                    if addr not in clients:
                        if message_decoded.startswith("SIGNUP_TAG:"):
                            data = message_decoded.split(":")
                            if len(data) == 3:
                                name, password = data[1], data[2]

                                if password == PASSWORD:
                                    if name not in clients.values():
                                        clients[addr] = name
                                        server.sendto(f"Welcome, {name}! You have joined the chat.".encode(), addr)
                                        log_area.insert(tk.END, f"New client joined: {name} from {addr}\n")
                                        log_area.yview(tk.END)

                                        # Broadcast that a new client has joined
                                        for client_addr in clients:
                                            if client_addr != addr:
                                                server.sendto(f"{name} has joined the chat.".encode(), client_addr)
                                    else:
                                        server.sendto("Username already in use!".encode(), addr)
                                else:
                                    server.sendto("Incorrect password!".encode(), addr)
                                    log_area.insert(tk.END, f"Failed login attempt from {addr} with wrong password.\n")
                                    log_area.yview(tk.END)
                            else:
                                server.sendto("Invalid signup format.".encode(), addr)
                        else:
                            server.sendto("You need to login first.".encode(), addr)
                    else:
                        # Broadcast the message to all clients
                        for client_addr in list(clients):
                            if client_addr != addr:  # Don't send back to the sender
                                try:
                                    server.sendto(message, client_addr)
                                except:
                                    log_area.insert(tk.END, f"Client {clients[client_addr]} disconnected.\n")
                                    log_area.yview(tk.END)
                                    del clients[client_addr]

        t1 = threading.Thread(target=receive, daemon=True)
        t2 = threading.Thread(target=broadcast, daemon=True)

        threads.append(t1)
        threads.append(t2)

        t1.start()
        t2.start()

    except OSError as e:
        messagebox.showerror("Error", f"Failed to start server: {e}")
        log_area.insert(tk.END, f"Failed to bind to {server_ip}:{server_port}. Port might be in use or invalid.\n")
        log_area.yview(tk.END)
        is_server_running = False

def stop_server():
    global server, is_server_running, threads
    if server:
        is_server_running = False
        server.close()  # Close the server socket
        log_area.insert(tk.END, "Server stopped.\n")
        log_area.yview(tk.END)

        # Clean up the running threads
        for thread in threads:
            if thread.is_alive():
                thread.join()  # Wait for threads to finish
        threads.clear()  # Clear the threads list

def close_window():
    """Function to close the GUI window."""
    if messagebox.askyesno("Close Window", "Are you sure you want to close the application?"):
        stop_server()
        server_gui.destroy()  # Close the GUI after stopping the server

# Create buttons for starting, stopping, and closing the server
start_button = tk.Button(server_gui, text="Start Server", command=start_server, bg='green', fg='white')
start_button.pack(padx=10, pady=10)

stop_button = tk.Button(server_gui, text="Stop Server", command=stop_server, bg='orange', fg='black')
stop_button.pack(padx=10, pady=10)

close_button = tk.Button(server_gui, text="Close Window", command=close_window, bg='red', fg='white')
close_button.pack(padx=10, pady=10)

server_gui.protocol("WM_DELETE_WINDOW", close_window)  # Handle window close button
server_gui.mainloop()

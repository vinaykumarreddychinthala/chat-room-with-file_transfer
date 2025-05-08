import os
import sys
import socket
import threading
import struct
import time
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from pathlib import Path

class ClientApp:
    def __init__(self, root, server_ip_arg=None): # Renamed server_ip to server_ip_arg for clarity
        self.root = root
        self.root.title("Chat-Room")
        self.initial_server_ip = server_ip_arg # Store the initial IP from argument
        self.server_ip = server_ip_arg # Current server IP to connect to
        self.socket = None
        self.username = None
        self.connected = False
        self.heartbeat_active = False
        self.last_activity = time.time()
        self.download_dir = str(Path.home() / "Downloads")
        os.makedirs(self.download_dir, exist_ok=True)
        
        self.setup_ui()
    def setup_ui(self):
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Connection Frame
        self.conn_frame = tk.Frame(self.root)
        self.conn_frame.pack(pady=10, fill=tk.X)
        
        tk.Label(self.conn_frame, text="Server IP:").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(self.conn_frame, width=20)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        if self.initial_server_ip:
            self.ip_entry.insert(0, self.initial_server_ip)
            self.ip_entry.config(state='disabled')
        else:
            self.ip_entry.insert(0, "localhost") # Default if no arg
        
        tk.Label(self.conn_frame, text="Username:").pack(side=tk.LEFT)
        self.user_entry = tk.Entry(self.conn_frame)
        self.user_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = tk.Button(self.conn_frame, text="Connect", command=self.connect_to_server)
        self.connect_btn.pack(side=tk.LEFT)
        
        # Chat Display
        self.chat_display = scrolledtext.ScrolledText(
            self.root, 
            state='disabled', 
            wrap=tk.WORD,
            font=('Arial', 10)
        )
        self.chat_display.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.chat_display.tag_config('them', foreground='blue', justify='left')
        self.chat_display.tag_config('me', foreground='green', justify='right')
        self.chat_display.tag_config('system', foreground='gray', justify='center')
        self.show_placeholder()
        
        # Message Entry
        self.msg_frame = tk.Frame(self.root)
        self.msg_frame.pack(pady=5, fill=tk.X, padx=10)
        
        self.msg_entry = tk.Entry(self.msg_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        
        self.send_btn = tk.Button(self.msg_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.LEFT, padx=5)
        
        self.file_btn = tk.Button(self.msg_frame, text="Send File", command=self.send_file_dialog)
        self.file_btn.pack(side=tk.LEFT)
        
        # User List
        self.user_list = tk.Listbox(self.root)
        self.user_list.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.user_list.bind("<<ListboxSelect>>", self.select_user)
        
        self.status_bar = tk.Label(self.root, text="Not connected", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X)
        
        self.current_chat = None
        self.conversations = {}

    def show_placeholder(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.insert(tk.END, "Select a user from the list to start chatting", "system")
        self.chat_display.config(state='disabled')

    def connect_to_server(self):
        if self.connected:
            return
            
        self.server_ip = self.ip_entry.get().strip() or "localhost"
        attempted_username = self.user_entry.get().strip()
        
        if not attempted_username:
            messagebox.showerror("Error", "Please enter a username")
            return
            
        temp_socket = None
        try:
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_socket.settimeout(10) 
            temp_socket.connect((self.server_ip, 5001))
            
            temp_socket.sendall(attempted_username.encode())
            
            # Wait for server response (CONN_OK or NAMEINUSE)
            header = temp_socket.recv(4)
            if not header:
                raise ConnectionError("Server closed connection prematurely.")
            
            length = struct.unpack('!I', header)[0]
            response_data = b''
            while len(response_data) < length:
                chunk = temp_socket.recv(length - len(response_data))
                if not chunk:
                    raise ConnectionError("Incomplete response from server.")
                response_data += chunk

            if response_data == b"NAMEINUSE":
                messagebox.showerror("Error", "Username is already in use.")
                temp_socket.close()
                # Ensure UI is in correct state for another attempt
                self.user_entry.config(state='normal') # Allow re-editing username
                if not self.initial_server_ip: # If IP was not from arg, allow editing
                    self.ip_entry.config(state='normal')
                return 
            elif response_data == b"CONN_OK":
                self.socket = temp_socket
                self.username = attempted_username
                self.socket.settimeout(None)
                
                self.connected = True
                self.heartbeat_active = True
                self.status_bar.config(text=f"Connected to {self.server_ip} as {self.username}")
                self.connect_btn.config(text="Disconnect", command=self.disconnect)
                self.ip_entry.config(state='disabled') # Disable after successful connect
                self.user_entry.config(state='disabled')# Disable after successful connect
                
                self.current_chat = None 
                self.conversations = {} 
                self.show_placeholder() 

                threading.Thread(target=self.heartbeat, daemon=True).start()
                threading.Thread(target=self.receive_data, daemon=True).start()
            else:
                messagebox.showerror("Error", f"Unexpected response from server: {response_data.decode(errors='ignore')}")
                temp_socket.close()
                return

        except socket.timeout:
            messagebox.showerror("Error", "Connection or server response timed out")
            if temp_socket: temp_socket.close()
            self._handle_connection_fail_ui_reset()
        except ConnectionRefusedError:
            messagebox.showerror("Error", "Connection refused. Is the server running?")
            if temp_socket: temp_socket.close()
            self._handle_connection_fail_ui_reset()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {e}")
            if temp_socket: temp_socket.close()
            self._handle_connection_fail_ui_reset()

    def _handle_connection_fail_ui_reset(self):
        self.connected = False
        self.heartbeat_active = False
        self.socket = None
        self.status_bar.config(text="Failed to connect")
        self.connect_btn.config(text="Connect", command=self.connect_to_server)
        if not self.initial_server_ip: # Only enable IP if not passed as arg
            self.ip_entry.config(state='normal')
        self.user_entry.config(state='normal') # Always enable user entry on fail

    def heartbeat(self):
        while self.heartbeat_active and self.connected:
            try:
                time.sleep(10)
                if self.connected and self.socket: # Check socket too
                    self.socket.sendall(struct.pack('!I', 9) + b"HEARTBEAT")
                    self.last_activity = time.time()
            except:
                if self.connected: # Avoid multiple disconnect calls if already disconnecting
                    self.root.after(0, self.disconnect)
                break

    def disconnect(self):
        # Prevent repeated disconnect calls if already in progress
        if not self.connected and not self.heartbeat_active and self.socket is None:
             # If already fully disconnected, ensure UI is consistent and return
            if self.connect_btn.cget('text') != "Connect":
                 self._reset_ui_to_disconnected_state()
            return

        self.heartbeat_active = False # Stop heartbeat loop first
        
        # Close socket in a try-except block
        if self.socket:
            try:
                self.socket.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
            finally:
                self.socket = None # Ensure socket is None after attempting to close
        
        self.connected = False
        self._reset_ui_to_disconnected_state()


    def _reset_ui_to_disconnected_state(self):
        self.status_bar.config(text="Disconnected")
        self.connect_btn.config(text="Connect", command=self.connect_to_server)
        
        if not self.initial_server_ip: # Only enable IP if not passed as arg
            self.ip_entry.config(state='normal')
        # else it remains disabled if initial_server_ip was set

        self.user_entry.config(state='normal') # Always re-enable user entry
        
        self.user_list.delete(0, tk.END)
        self.conversations = {}
        self.current_chat = None
        self.username = None # Clear username on disconnect
        self.show_placeholder()


    def on_close(self):
        self.disconnect()
        self.root.destroy()

    def receive_data(self):
        while self.connected and self.socket:
            try:
                header = self.socket.recv(4)
                if not header: # Connection closed by server
                    break 
                    
                length = struct.unpack('!I', header)[0]
                data = b''
                while len(data) < length:
                    chunk = self.socket.recv(min(4096, length - len(data)))
                    if not chunk: # Connection broken during read
                        raise ConnectionError("Incomplete data received, connection likely broken.")
                    data += chunk
                
                if data == b"HEARTBEAT":
                    continue
                elif data.startswith(b"USERLIST:"):
                    self.root.after(0, self.update_user_list, data[9:].decode())
                elif data.startswith(b"MSG:"):
                    self.root.after(0, self.handle_message, data[4:])
                elif data.startswith(b"FILE:"):
                    self.root.after(0, self.handle_file, data[5:])
                elif data.startswith(b"USERDISCONNECTED:"):
                    disconnected_user = data[17:].decode() # Corrected length for "USERDISCONNECTED:"
                    self.root.after(0, self.handle_user_disconnected, disconnected_user)
                    
            except socket.timeout: # Should not happen if socket.settimeout(None)
                continue
            except ConnectionError as e: # Covers ConnectionResetError, custom ConnectionError
                print(f"Connection error in receive_data: {e}")
                break
            except Exception as e:
                print(f"Receive error: {e}")
                break
        
        if self.connected: # If loop broke due to error/closure while still "logically" connected
            self.root.after(0, self.disconnect)


    def update_user_list(self, user_list_str):
        selected_user_before_update = self.current_chat
        
        self.user_list.delete(0, tk.END)
        users = user_list_str.split(',') if user_list_str else []
        
        new_list_for_widget = []
        for user in users:
            if user != self.username: # Don't list self
                new_list_for_widget.append(user)
                self.user_list.insert(tk.END, user)
        
        if selected_user_before_update in new_list_for_widget:
            try:
                idx = new_list_for_widget.index(selected_user_before_update)
                self.user_list.selection_set(idx)
                self.user_list.activate(idx) # Ensure it's visibly selected
                self.current_chat = selected_user_before_update # Re-affirm
            except ValueError: # Should not happen if check `in new_list_for_widget` is correct
                self.current_chat = None
                self.show_placeholder()
        elif self.current_chat and self.current_chat not in new_list_for_widget : # If current chat user disconnected
            self.current_chat = None
            self.show_placeholder()
        # If no selection or previous selection gone, placeholder remains or is set


    def handle_user_disconnected(self, username_disconnected):
        if username_disconnected in self.conversations:
            del self.conversations[username_disconnected] 
        
        if self.current_chat == username_disconnected:
            self.current_chat = None
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.insert(tk.END, f"{username_disconnected} has disconnected. Select another user.", "system")
            self.chat_display.config(state='disabled')
        # The user_list widget will be updated by the next USERLIST message from the server.

    def get_user_list_from_widget(self): # Renamed to avoid conflict
        return [self.user_list.get(i) for i in range(self.user_list.size())]

    def select_user(self, event):
        selection = self.user_list.curselection()
        if selection:
            selected_username = self.user_list.get(selection[0])
            if selected_username != self.current_chat: # Only update if selection changed
                self.current_chat = selected_username
                self.status_bar.config(text=f"Chatting with {self.current_chat}")
                self.update_chat_display()

    def update_chat_display(self):
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        
        if self.current_chat and self.current_chat in self.conversations:
            for msg_data in self.conversations[self.current_chat]:
                # Assuming msg_data is (message_text, tag)
                self.chat_display.insert(tk.END, msg_data[0], msg_data[1])
        elif not self.current_chat:
             self.show_placeholder() # If current_chat became None
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def _add_message_to_conversation(self, target_user, message_text, tag):
        if target_user not in self.conversations:
            self.conversations[target_user] = []
        self.conversations[target_user].append((message_text, tag))


    def handle_message(self, data):
        sender, _, message_content = data.partition(b":")
        sender = sender.decode()
        message_content = message_content.decode()
        
        timestamp = time.strftime("%H:%M")
        formatted_msg = f"[{timestamp}] {sender}: {message_content}\n"
        
        self._add_message_to_conversation(sender, formatted_msg, 'them')
        
        if sender == self.current_chat:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, formatted_msg, 'them')
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
        else:
            # Notify user of new message from non-active chat if desired (e.g., change user color in list)
            pass


    def send_message(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
            
        if not self.current_chat:
            messagebox.showwarning("Warning", "Please select a user to chat with")
            return
            
        message = self.msg_entry.get().strip()
        if not message:
            return
            
        try:
            data_to_send = f"CHAT:{self.current_chat}:{message}".encode()
            self.socket.sendall(struct.pack('!I', len(data_to_send)) + data_to_send)
            
            timestamp = time.strftime("%H:%M")
            formatted_sent_msg = f"[{timestamp}] You: {message}\n"
            self._add_message_to_conversation(self.current_chat, formatted_sent_msg, 'me')
            
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, formatted_sent_msg, 'me')
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)
            
            self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
            self.disconnect()

    def send_file_dialog(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return
            
        if not self.current_chat:
            messagebox.showwarning("Warning", "Please select a user to send files to")
            return
            
        filepath = filedialog.askopenfilename()
        if filepath:
            threading.Thread(target=self.send_file, args=(filepath,), daemon=True).start()

    def send_file(self, filepath):
        try:
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            
            with open(filepath, 'rb') as f:
                filedata = f.read()
                
            header = f"FILE:{self.current_chat}:{filename}:{filesize}:".encode()
            self.socket.sendall(struct.pack('!I', len(header)+filesize) + header + filedata)
            
            timestamp = time.strftime("%H:%M")
            formatted_file_sent_msg = f"[{timestamp}] You: Sent file: {filename}\n"
            self._add_message_to_conversation(self.current_chat, formatted_file_sent_msg, 'me')
            
            self.root.after(0, lambda: self.display_message_in_chat(formatted_file_sent_msg, 'me'))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send file: {e}")
            if self.connected: self.root.after(0, self.disconnect)


    def handle_file(self, data):
        try:
            parts = data.split(b":", 3)
            if len(parts) != 4:
                raise ValueError("Invalid file message format")
                
            sender = parts[0].decode()
            filename = parts[1].decode()
            filesize = int(parts[2].decode())
            filedata_received = parts[3]
            
            if len(filedata_received) != filesize: # Check if all data is there
                raise ValueError(f"File size mismatch. Expected {filesize}, got {len(filedata_received)}")
                
            save_path = os.path.join(self.download_dir, filename)
            base, ext = os.path.splitext(save_path)
            counter = 1
            while os.path.exists(save_path):
                save_path = f"{base}_{counter}{ext}"
                counter += 1
                
            with open(save_path, 'wb') as f:
                f.write(filedata_received)
                
            timestamp = time.strftime("%H:%M")
            formatted_file_recv_msg = f"[{timestamp}] {sender}: Sent file: {filename}\n"
            self._add_message_to_conversation(sender, formatted_file_recv_msg, 'them')
            
            self.root.after(0, lambda: self.display_message_in_chat(formatted_file_recv_msg, 'them', sender_is_originator=sender))
            self.root.after(0, lambda: messagebox.showinfo(
                "File Received", 
                f"Received {filename} from {sender}\nSaved to: {save_path}"
            ))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to receive file: {e}")

    def display_message_in_chat(self, message, tag, sender_is_originator=None):

        display_condition = False
        if tag == 'me' and self.current_chat: # Message from self to current_chat
             display_condition = True
        elif tag == 'them' and self.current_chat == sender_is_originator: # Message from sender_is_originator to self, and current chat is with them
             display_condition = True

        if display_condition:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, message, tag)
            self.chat_display.config(state='disabled')
            self.chat_display.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    # Pass server IP from command line if provided, otherwise None
    arg_server_ip = sys.argv[1] if len(sys.argv) > 1 else None
    app = ClientApp(root, server_ip_arg=arg_server_ip)
    root.mainloop()

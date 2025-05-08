import socket
import threading
import struct
import time
from queue import Queue
import sys 

class Server:
    def __init__(self, port=5001):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.settimeout(1) 
        self.server_socket.bind(('0.0.0.0', port))
        self.server_socket.listen(10)
        
        self.clients = {}  # socket: username
        self.lock = threading.Lock()
        self.running = True
        self.heartbeat_interval = 15
        
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            host_ip = '127.0.0.1' 
        print(f"Server started on {host_ip}:{port} (listening on 0.0.0.0)")
        print("Waiting for connections...")
        
        threading.Thread(target=self.client_maintenance, daemon=True).start()
        self.run()

    def client_maintenance(self):
        while self.running:
            time.sleep(self.heartbeat_interval)
            with self.lock:
                for client_socket in list(self.clients.keys()): 
                    if client_socket not in self.clients: 
                        continue
                    try:
                        client_socket.sendall(struct.pack('!I', 9) + b"HEARTBEAT")
                    except:
                        # If send fails, schedule removal.
                        username_for_log = self.clients.get(client_socket, 'unknown client')
                        print(f"Heartbeat send failed for {username_for_log}. Removing.")
                        # Pass a reason for removal
                        self.remove_client(client_socket, "Heartbeat failed") 

    def broadcast(self, message_bytes, exclude_socket=None):
        with self.lock:
            current_clients = list(self.clients.keys()) 
            for client in current_clients:
                if client != exclude_socket and client in self.clients: 
                    try:
                        client.sendall(message_bytes)
                    except:
                        self.remove_client(client, "Broadcast send failed")

    def broadcast_formatted_message(self, message_str, exclude_socket=None):
        encoded = message_str.encode()
        header = struct.pack('!I', len(encoded))
        self.broadcast(header + encoded, exclude_socket)

    def remove_client(self, client_socket, reason=""):
        username_removed = None
        with self.lock:
            if client_socket in self.clients:
                username_removed = self.clients.pop(client_socket)
                print(f"Client {username_removed or client_socket.getpeername()} disconnected. Reason: {reason or 'Connection lost'}")
        
        try:
            client_socket.close()
        except:
            pass 
        
        if username_removed: 
            self.broadcast_formatted_message(f"USERDISCONNECTED:{username_removed}")
            self.update_user_list_broadcast() 

    def update_user_list_broadcast(self):
        with self.lock:
            user_list_str = ",".join(self.clients.values())
        self.broadcast_formatted_message(f"USERLIST:{user_list_str}")

    def handle_client(self, client_socket):
        username = None 
        client_added_to_list = False
        
        # Variables to store exception information if one occurs in the outer try block
        outer_exception_type = None
        outer_exception_value = None
        outer_exception_traceback = None

        try:
            client_socket.settimeout(10) 
            username_bytes = client_socket.recv(1024) 
            if not username_bytes:
                # No self.remove_client here; finally block will handle it with default reason
                return

            username = username_bytes.decode().strip()
            
            if not username:
                # No self.remove_client here; finally block will handle it
                return
                
            with self.lock:
                if username in self.clients.values():
                    print(f"Username '{username}' already in use. Rejecting {client_socket.getpeername()}.")
                    msg = b"NAMEINUSE"
                    client_socket.sendall(struct.pack('!I', len(msg)) + msg)
                    return 
            
            msg_ok = b"CONN_OK"
            client_socket.sendall(struct.pack('!I', len(msg_ok)) + msg_ok)
            
            client_socket.settimeout(None) 
            with self.lock:
                self.clients[client_socket] = username
                client_added_to_list = True 
            
            print(f"{username} connected from {client_socket.getpeername()}")
            self.update_user_list_broadcast() 

            while self.running and client_socket in self.clients: 
                try:
                    header = client_socket.recv(4)
                    if not header: 
                        break 
                        
                    length = struct.unpack('!I', header)[0]
                    data = b''
                    while len(data) < length:
                        chunk = client_socket.recv(min(4096, length - len(data)))
                        if not chunk: 
                            raise ConnectionError("Incomplete data, client likely disconnected.")
                        data += chunk
                    
                    if data == b"HEARTBEAT":
                        continue 
                    elif data.startswith(b"CHAT:"):
                        _, recipient_and_message = data.split(b":", 1)
                        recipient, message_content = recipient_and_message.split(b":", 1)
                        self.route_message(username, recipient.decode(), message_content.decode())
                    elif data.startswith(b"FILE:"):
                        self.handle_file_transfer(username, data[5:])

                except socket.timeout: 
                    continue
                except ConnectionError: 
                    break 
                except Exception as e_loop:
                    print(f"Error handling client {username} in loop: {e_loop}")
                    break 

        except socket.timeout: 
            outer_exception_type, outer_exception_value, outer_exception_traceback = sys.exc_info()
            print(f"Timeout waiting for username from {client_socket.getpeername()}.")
        except Exception: 
            outer_exception_type, outer_exception_value, outer_exception_traceback = sys.exc_info()
            print(f"Error during client handshake ({username or client_socket.getpeername()}): {outer_exception_value}")
        finally:
            reason_for_removal = "Handler exit" # Default reason

            # Check if an exception was caught by the outer try-except blocks
            current_exception_being_handled = outer_exception_value
            
            if current_exception_being_handled:
                if isinstance(current_exception_being_handled, ConnectionError):
                    reason_for_removal = "Connection error"
                elif isinstance(current_exception_being_handled, socket.timeout):
                    reason_for_removal = "Timeout during handshake"
                else:
                    reason_for_removal = f"Handshake Exception: {type(current_exception_being_handled).__name__}"
            
            self.remove_client(client_socket, reason_for_removal)


    def route_message(self, sender_username, recipient_username, message_text):
        if recipient_username.lower() == "all": 
            formatted_msg_str = f"MSG:{sender_username}:{message_text}"
            self.broadcast_formatted_message(formatted_msg_str) 
        else:
            target_socket = None
            with self.lock:
                for sock, uname in self.clients.items():
                    if uname == recipient_username:
                        target_socket = sock
                        break
            
            if target_socket:
                try:
                    msg_to_send = f"MSG:{sender_username}:{message_text}".encode()
                    target_socket.sendall(struct.pack('!I', len(msg_to_send)) + msg_to_send)
                except:
                    self.remove_client(target_socket, "Failed to send message")
            else:
                print(f"Recipient {recipient_username} not found for message from {sender_username}.")


    def handle_file_transfer(self, sender_username, file_protocol_data):
        try:
            parts = file_protocol_data.split(b":", 3)
            if len(parts) != 4:
                raise ValueError("Invalid file transfer format (not enough parts)")
                
            recipient_username = parts[0].decode()
            filename = parts[1].decode() 
            filesize = int(parts[2].decode())
            actual_file_data = parts[3]
            
            if len(actual_file_data) != filesize:
                raise ValueError(f"File size mismatch for {filename}. Expected {filesize}, got {len(actual_file_data)}")
            
            target_socket = None
            with self.lock:
                for sock, uname in self.clients.items():
                    if uname == recipient_username:
                        target_socket = sock
                        break
            
            if target_socket:
                try:
                    header_for_recipient = f"FILE:{sender_username}:{filename}:{filesize}:".encode()
                    full_data_to_send = header_for_recipient + actual_file_data
                    
                    target_socket.sendall(struct.pack('!I', len(full_data_to_send)) + full_data_to_send)
                except:
                    self.remove_client(target_socket, f"Failed to relay file to {recipient_username}")
            else:
                print(f"Recipient {recipient_username} not found for file from {sender_username}.")

        except Exception as e:
            print(f"File transfer routing error from {sender_username}: {e}")

    def run(self):
        try:
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"Accepted connection from {addr}")
                    threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
                except socket.timeout:
                    continue 
                except Exception as e:
                    if self.running: 
                        print(f"Error accepting connections: {e}")
                    break 
        except KeyboardInterrupt:
            print("\nShutting down server (KeyboardInterrupt)...")
        finally:
            self.running = False
            print("Closing client connections...")
            with self.lock:
                for client_sock in list(self.clients.keys()):
                    try:
                        client_sock.close()
                    except:
                        pass
                self.clients.clear()
            self.server_socket.close()
            print("Server shutdown complete.")

if __name__ == "__main__":
    server = Server()
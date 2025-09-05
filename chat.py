import asyncio
import argparse
import socket
import struct
import logging
import json
import base64
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import signal
import sys

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("kademlia").setLevel(logging.WARNING)

# Constants
MAX_MESSAGE_SIZE = 1024 * 64  # 64KB
HEARTBEAT_INTERVAL = 30  # seconds
CONNECTION_TIMEOUT = 10  # seconds
RECONNECT_DELAY = 5  # seconds

@dataclass
class PeerConnection:
    """Represents a peer connection with encryption keys"""
    writer: asyncio.StreamWriter
    public_key: Optional[rsa.RSAPublicKey] = None
    username: Optional[str] = None
    last_heartbeat: float = 0
    authenticated: bool = False

class SecureP2PChat:
    def __init__(self):
        self.chat_connections: Dict[Tuple[str, int], PeerConnection] = {}
        self.connections_lock = asyncio.Lock()
        self.private_key = None
        self.public_key = None
        self.username = None
        self.dht_server = None
        self.local_ip = None
        self.chat_port = None
        self.running = False
        self.server = None
        
    def generate_keys(self):
        """Generate RSA key pair for this user"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        logging.info("🔐 Generated RSA key pair")
    
    def serialize_public_key(self) -> str:
        """Serialize public key to string for transmission"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pem).decode('utf-8')
    
    def deserialize_public_key(self, key_str: str) -> rsa.RSAPublicKey:
        """Deserialize public key from string"""
        pem = base64.b64decode(key_str.encode('utf-8'))
        return serialization.load_pem_public_key(pem)
    
    def encrypt_message(self, message: str, public_key: rsa.RSAPublicKey) -> str:
        """Encrypt message with AES + RSA hybrid encryption"""
        # Generate AES key
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV
        
        # Encrypt message with AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad message to multiple of 16 bytes
        padded_message = message.encode('utf-8')
        padding_len = 16 - (len(padded_message) % 16)
        padded_message += bytes([padding_len] * padding_len)
        
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine encrypted key, IV, and encrypted message
        result = {
            'key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'data': base64.b64encode(encrypted_message).decode('utf-8')
        }
        
        return json.dumps(result)
    
    def decrypt_message(self, encrypted_data: str) -> str:
        """Decrypt message with AES + RSA hybrid decryption"""
        try:
            data = json.loads(encrypted_data)
            
            # Decrypt AES key with RSA
            encrypted_key = base64.b64decode(data['key'])
            aes_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message with AES
            iv = base64.b64decode(data['iv'])
            encrypted_message = base64.b64decode(data['data'])
            
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
            
            # Remove padding
            padding_len = padded_message[-1]
            message = padded_message[:-padding_len]
            
            return message.decode('utf-8')
        except Exception as e:
            logging.error(f"Failed to decrypt message: {e}")
            return "[DECRYPTION FAILED]"
    
    def sign_message(self, message: str) -> str:
        """Sign a message with private key"""
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message: str, signature_str: str, public_key: rsa.RSAPublicKey) -> bool:
        """Verify message signature"""
        try:
            signature = base64.b64decode(signature_str)
            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    async def send_message(self, writer: asyncio.StreamWriter, message_type: str, data: dict):
        """Send a structured message to a peer"""
        try:
            message = {
                'type': message_type,
                'timestamp': time.time(),
                'data': data
            }
            
            if message_type != 'handshake':
                message['signature'] = self.sign_message(json.dumps(data, sort_keys=True))
            
            serialized = json.dumps(message).encode('utf-8')
            
            if len(serialized) > MAX_MESSAGE_SIZE:
                raise ValueError("Message too large")
            
            header = struct.pack('!I', len(serialized))
            writer.write(header + serialized)
            await writer.drain()
        except Exception as e:
            logging.error(f"Failed to send message: {e}")
            raise
    
    async def receive_message(self, reader: asyncio.StreamReader) -> Optional[dict]:
        """Receive and parse a structured message"""
        try:
            # Read header
            header = await asyncio.wait_for(reader.readexactly(4), timeout=CONNECTION_TIMEOUT)
            message_len = struct.unpack('!I', header)[0]
            
            if message_len > MAX_MESSAGE_SIZE:
                raise ValueError("Message too large")
            
            # Read message
            data = await asyncio.wait_for(reader.readexactly(message_len), timeout=CONNECTION_TIMEOUT)
            message = json.loads(data.decode('utf-8'))
            
            return message
        except asyncio.TimeoutError:
            raise ConnectionError("Message receive timeout")
        except Exception as e:
            logging.error(f"Failed to receive message: {e}")
            return None
    
    async def perform_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_initiator: bool) -> bool:
        """Perform secure handshake with peer"""
        try:
            if is_initiator:
                # Send our public key and username
                await self.send_message(writer, 'handshake', {
                    'username': self.username,
                    'public_key': self.serialize_public_key()
                })
                
                # Receive peer's handshake
                response = await self.receive_message(reader)
                if not response or response['type'] != 'handshake':
                    return False
                
                peer_data = response['data']
            else:
                # Receive initiator's handshake
                message = await self.receive_message(reader)
                if not message or message['type'] != 'handshake':
                    return False
                
                peer_data = message['data']
                
                # Send our response
                await self.send_message(writer, 'handshake', {
                    'username': self.username,
                    'public_key': self.serialize_public_key()
                })
            
            # Verify and store peer info
            peer_username = peer_data['username']
            peer_public_key = self.deserialize_public_key(peer_data['public_key'])
            
            peer_addr = writer.get_extra_info('peername')
            async with self.connections_lock:
                if peer_addr in self.chat_connections:
                    self.chat_connections[peer_addr].public_key = peer_public_key
                    self.chat_connections[peer_addr].username = peer_username
                    self.chat_connections[peer_addr].authenticated = True
                    self.chat_connections[peer_addr].last_heartbeat = time.time()
            
            logging.info(f"🤝 Authenticated with {peer_username} ({peer_addr[0]}:{peer_addr[1]})")
            return True
            
        except Exception as e:
            logging.error(f"Handshake failed: {e}")
            return False
    
    async def handle_chat_session(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_initiator: bool = False):
        """Handle a chat session with a peer"""
        peer_addr = writer.get_extra_info('peername')
        
        try:
            # Add to connections
            async with self.connections_lock:
                self.chat_connections[peer_addr] = PeerConnection(writer=writer)
            
            # Perform handshake
            if not await self.perform_handshake(reader, writer, is_initiator):
                logging.error(f"❌ Handshake failed with {peer_addr}")
                return
            
            # Handle messages
            while self.running:
                message = await self.receive_message(reader)
                if not message:
                    break
                
                await self.process_message(message, peer_addr)
                
        except (ConnectionResetError, asyncio.IncompleteReadError, ConnectionAbortedError, ConnectionError):
            logging.warning(f"🔌 Connection with {peer_addr} lost")
        except Exception as e:
            logging.error(f"Error in chat session with {peer_addr}: {e}")
        finally:
            await self.cleanup_connection(peer_addr)
    
    async def process_message(self, message: dict, peer_addr: Tuple[str, int]):
        """Process received message from peer"""
        msg_type = message.get('type')
        data = message.get('data', {})
        
        async with self.connections_lock:
            peer_conn = self.chat_connections.get(peer_addr)
            if not peer_conn or not peer_conn.authenticated:
                logging.warning(f"Received message from unauthenticated peer {peer_addr}")
                return
        
        if msg_type == 'chat':
            # Decrypt and display chat message
            encrypted_content = data.get('content')
            if encrypted_content:
                decrypted_msg = self.decrypt_message(encrypted_content)
                username = peer_conn.username or f"{peer_addr[0]}:{peer_addr[1]}"
                print(f"\r<{username}> {decrypted_msg}\n> ", end="", flush=True)
        
        elif msg_type == 'heartbeat':
            # Update last heartbeat time
            async with self.connections_lock:
                if peer_addr in self.chat_connections:
                    self.chat_connections[peer_addr].last_heartbeat = time.time()
            
            # Send heartbeat response
            try:
                await self.send_message(peer_conn.writer, 'heartbeat_ack', {})
            except Exception:
                pass  # Connection might be dead
        
        elif msg_type == 'heartbeat_ack':
            # Update last heartbeat time
            async with self.connections_lock:
                if peer_addr in self.chat_connections:
                    self.chat_connections[peer_addr].last_heartbeat = time.time()
    
    async def cleanup_connection(self, peer_addr: Tuple[str, int]):
        """Clean up a connection"""
        async with self.connections_lock:
            if peer_addr in self.chat_connections:
                peer_conn = self.chat_connections[peer_addr]
                try:
                    peer_conn.writer.close()
                    await peer_conn.writer.wait_closed()
                except Exception:
                    pass
                del self.chat_connections[peer_addr]
        
        logging.info(f"Cleaned up connection with {peer_addr}")
    
    async def listen_for_chats(self, host: str, port: int):
        """Listen for incoming chat connections"""
        try:
            self.server = await asyncio.start_server(
                lambda r, w: self.handle_chat_session(r, w, False), 
                host, port
            )
            addr = self.server.sockets[0].getsockname()
            logging.info(f"💬 Chat server listening on {addr}")
            
            async with self.server:
                await self.server.serve_forever()
        except asyncio.CancelledError:
            logging.info("Chat server cancelled")
        except Exception as e:
            logging.error(f"❌ Chat server error: {e}")
    
    async def heartbeat_monitor(self):
        """Monitor connections with heartbeat"""
        while self.running:
            try:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                
                current_time = time.time()
                dead_connections = []
                
                async with self.connections_lock:
                    for addr, peer_conn in self.chat_connections.items():
                        if peer_conn.authenticated:
                            # Send heartbeat
                            try:
                                await self.send_message(peer_conn.writer, 'heartbeat', {})
                            except Exception:
                                dead_connections.append(addr)
                                continue
                            
                            # Check if peer is responsive
                            if current_time - peer_conn.last_heartbeat > HEARTBEAT_INTERVAL * 3:
                                logging.warning(f"Peer {addr} not responding to heartbeat")
                                dead_connections.append(addr)
                
                # Clean up dead connections
                for addr in dead_connections:
                    await self.cleanup_connection(addr)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Heartbeat monitor error: {e}")
    
    async def connect_to_peer(self, username: str) -> bool:
        """Connect to a peer by username"""
        if username == self.username:
            print("You can't connect to yourself!")
            return False
        
        # Check if already connected
        async with self.connections_lock:
            for peer_conn in self.chat_connections.values():
                if peer_conn.username == username:
                    print(f"Already connected to {username}")
                    return True
        
        logging.info(f"🔍 Searching for '{username}'...")
        friend_location = await self.dht_server.get(username)
        
        if not friend_location:
            logging.warning(f"❌ User '{username}' not found.")
            return False
        
        try:
            friend_ip, friend_port = friend_location.split(':')
            logging.info(f"✅ Found '{username}' at {friend_location}")
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(friend_ip, int(friend_port)),
                timeout=CONNECTION_TIMEOUT
            )
            
            # Start chat session in background
            asyncio.create_task(self.handle_chat_session(reader, writer, True))
            return True
            
        except Exception as e:
            logging.error(f"❌ Failed to connect to {username}: {e}")
            return False
    
    async def broadcast_message(self, message: str):
        """Send message to all connected peers"""
        if not message.strip():
            return
        
        dead_connections = []
        
        async with self.connections_lock:
            connections = list(self.chat_connections.items())
        
        for addr, peer_conn in connections:
            if not peer_conn.authenticated or not peer_conn.public_key:
                continue
            
            try:
                encrypted_msg = self.encrypt_message(message, peer_conn.public_key)
                await self.send_message(peer_conn.writer, 'chat', {
                    'content': encrypted_msg
                })
            except Exception as e:
                logging.error(f"Failed to send message to {addr}: {e}")
                dead_connections.append(addr)
        
        # Clean up failed connections
        for addr in dead_connections:
            await self.cleanup_connection(addr)
    
    def get_local_ip(self) -> str:
        """Auto-detect local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            logging.warning("⚠️ Could not auto-detect local IP. Using 127.0.0.1")
            return '127.0.0.1'
    
    async def shutdown(self):
        """Gracefully shutdown the application"""
        logging.info("👋 Shutting down...")
        self.running = False
        
        # Close all connections
        async with self.connections_lock:
            for peer_conn in self.chat_connections.values():
                try:
                    peer_conn.writer.close()
                    await peer_conn.writer.wait_closed()
                except Exception:
                    pass
            self.chat_connections.clear()
        
        # Stop servers
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        if self.dht_server:
            self.dht_server.stop()
    
    async def run(self, args):
        """Main application loop"""
        self.username = args.username
        self.chat_port = args.chat_port
        
        if args.dht_port == args.chat_port:
            logging.error("❌ DHT and chat ports must be different!")
            return
        
        # Generate encryption keys
        self.generate_keys()
        
        # Get local IP
        self.local_ip = self.get_local_ip()
        
        try:
            # Start DHT server
            from kademlia.network import Server
            self.dht_server = Server()
            await self.dht_server.listen(args.dht_port)
            logging.info(f"🚀 Kademlia DHT server started on port {args.dht_port}")
            
            # Bootstrap if specified
            if args.bootstrap:
                try:
                    bootstrap_ip, bootstrap_port = args.bootstrap.split(':')
                    await self.dht_server.bootstrap([(bootstrap_ip, int(bootstrap_port))])
                    logging.info(f"✅ Bootstrapped to {args.bootstrap}")
                except Exception as e:
                    logging.error(f"❌ Failed to bootstrap to {args.bootstrap}: {e}")
                    return
            
            # Publish to DHT with signature
            dht_data = f"{self.local_ip}:{self.chat_port}"
            await self.dht_server.set(self.username, dht_data)
            logging.info(f"📢 Published '{self.username}' at {dht_data}")
            
            self.running = True
            
            # Start background tasks
            listener_task = asyncio.create_task(self.listen_for_chats(self.local_ip, self.chat_port))
            heartbeat_task = asyncio.create_task(self.heartbeat_monitor())
            
            # Setup signal handlers
            def signal_handler():
                asyncio.create_task(self.shutdown())
            
            if sys.platform != 'win32':
                loop = asyncio.get_running_loop()
                loop.add_signal_handler(signal.SIGINT, signal_handler)
                loop.add_signal_handler(signal.SIGTERM, signal_handler)
            
            print("\n🔐 Welcome to Secure Hushh!! Type /help for commands.")
            print("All messages are encrypted end-to-end.")
            
            # Main input loop
            try:
                import aioconsole
                use_aioconsole = True
            except ImportError:
                logging.warning("aioconsole not installed. Input will be blocking.")
                use_aioconsole = False
            
            while self.running:
                try:
                    if use_aioconsole:
                        command = await aioconsole.ainput("> ")
                    else:
                        command = await asyncio.to_thread(input, "> ")
                    
                    if not command.strip():
                        continue
                    
                    await self.handle_user_input(command.strip())
                    
                except (KeyboardInterrupt, EOFError):
                    break
                except Exception as e:
                    logging.error(f"Input error: {e}")
            
            # Wait for tasks to complete
            listener_task.cancel()
            heartbeat_task.cancel()
            await asyncio.gather(listener_task, heartbeat_task, return_exceptions=True)
            
        finally:
            await self.shutdown()
    
    async def handle_user_input(self, command: str):
        """Handle user input commands"""
        if command.startswith('/connect'):
            parts = command.split(maxsplit=1)
            if len(parts) != 2:
                print("Usage: /connect <username>")
                return
            await self.connect_to_peer(parts[1])
        
        elif command == '/help':
            print("""Commands:
  /connect <username> - Connect to a user
  /peers              - List connected peers  
  /disconnect <username> - Disconnect from a user
  /quit              - Exit the application
  
Any other text will be sent as an encrypted message to all connected peers.""")
        
        elif command == '/peers':
            async with self.connections_lock:
                authenticated_peers = [
                    (addr, peer.username) 
                    for addr, peer in self.chat_connections.items() 
                    if peer.authenticated
                ]
            
            if not authenticated_peers:
                print("Not connected to any peers.")
            else:
                print("Connected peers:")
                for i, (addr, username) in enumerate(authenticated_peers):
                    print(f"  {i+1}: {username or 'Unknown'} ({addr[0]}:{addr[1]})")
        
        elif command.startswith('/disconnect'):
            parts = command.split(maxsplit=1)
            if len(parts) != 2:
                print("Usage: /disconnect <username>")
                return
            
            username = parts[1]
            async with self.connections_lock:
                for addr, peer in list(self.chat_connections.items()):
                    if peer.username == username:
                        await self.cleanup_connection(addr)
                        print(f"Disconnected from {username}")
                        return
            print(f"Not connected to {username}")
        
        elif command == '/quit':
            self.running = False
        
        else:
            # Send as chat message
            async with self.connections_lock:
                peer_count = sum(1 for p in self.chat_connections.values() if p.authenticated)
            
            if peer_count == 0:
                print("You are not connected to anyone. Use /connect <username> to start a chat.")
                return
            
            await self.broadcast_message(command)

async def main():
    parser = argparse.ArgumentParser(description="Secure Decentralized P2P Chat 'Hushh!!'")
    parser.add_argument('--username', required=True, type=str, help='Your unique username')
    parser.add_argument('--dht-port', type=int, default=8468, help='Port for DHT node')
    parser.add_argument('--chat-port', type=int, default=8469, help='Port for chat server')
    parser.add_argument('--bootstrap', type=str, help='IP:PORT of bootstrap node')
    args = parser.parse_args()
    
    chat_app = SecureP2PChat()
    
    try:
        await chat_app.run(args)
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
    finally:
        await chat_app.shutdown()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
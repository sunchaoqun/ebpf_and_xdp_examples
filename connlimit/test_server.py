#!/usr/bin/env python3
"""
Simple TCP server for testing connection limiter
Listens on port 9015 and accepts connections
"""
import socket
import sys
import threading
import time

connections = []
conn_count = 0

def handle_client(conn, addr, conn_id):
    """Handle individual client connection"""
    try:
        # Don't send welcome message automatically (causes nc to stop in background)
        # Only send data when client sends first
        
        # Keep connection alive, echo any received data
        while True:
            data = conn.recv(1024)
            if not data:
                break
            # Echo back with connection info
            response = f"[Connection #{conn_id}] Received: {data.decode()}"
            conn.send(response.encode())
    except:
        pass
    finally:
        print(f"Connection #{conn_id} from {addr[0]}:{addr[1]} closed")
        conn.close()
        if conn in connections:
            connections.remove(conn)

def main():
    global conn_count
    port = 9015
    
    # Create socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', port))
        server.listen(500)  # Allow many connections
        print(f"✓ Test server listening on port {port}")
        print(f"  Max connections: 500")
        print(f"  Press Ctrl+C to stop")
        print()
        
        while True:
            conn, addr = server.accept()
            conn_count += 1
            connections.append(conn)
            print(f"✓ Connection #{conn_count} from {addr[0]}:{addr[1]} (Total: {len(connections)})")
            
            # Handle each connection in a separate thread
            thread = threading.Thread(target=handle_client, args=(conn, addr, conn_count))
            thread.daemon = True
            thread.start()
            
    except KeyboardInterrupt:
        print(f"\n\nShutting down...")
        print(f"Closing {len(connections)} active connections...")
        for conn in connections:
            try:
                conn.close()
            except:
                pass
    finally:
        server.close()
        print("Server stopped.")

if __name__ == "__main__":
    main()


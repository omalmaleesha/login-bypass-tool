#!/usr/bin/env python3
"""
Simple HTTP server for the Client-Side Authentication Security Lab
Serves static files and provides a convenient way to run the lab
"""

import http.server
import socketserver
import webbrowser
import os
import sys
from pathlib import Path

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Add security headers for educational purposes
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        super().end_headers()
    
    def log_message(self, format, *args):
        # Custom logging format
        print(f"[{self.log_date_time_string()}] {format % args}")

def start_server(port=8000, open_browser=True):
    """Start the HTTP server and optionally open browser"""
    
    # Change to the directory containing this script
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    
    # Check if required files exist
    required_files = ['index.html', 'auth.js', 'styles.css']
    missing_files = [f for f in required_files if not Path(f).exists()]
    
    if missing_files:
        print(f"Error: Missing required files: {', '.join(missing_files)}")
        sys.exit(1)
    
    try:
        with socketserver.TCPServer(("", port), CustomHTTPRequestHandler) as httpd:
            print(f"🚀 SecureBank Security Lab Server Starting...")
            print(f"📁 Serving files from: {script_dir}")
            print(f"🌐 Server running at: http://localhost:{port}")
            print(f"📖 Open the reverse engineering guide: reverse-engineering-guide.md")
            print(f"🐍 Run the bypass script: python bypass_automation.py")
            print(f"⚠️  Remember: This is for educational purposes only!")
            print(f"🛑 Press Ctrl+C to stop the server")
            print("-" * 60)
            
            if open_browser:
                print("🔍 Opening browser...")
                webbrowser.open(f'http://localhost:{port}')
            
            httpd.serve_forever()
            
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except OSError as e:
        if e.errno == 48:  # Address already in use
            print(f"❌ Error: Port {port} is already in use")
            print(f"💡 Try a different port: python server.py --port 8001")
        else:
            print(f"❌ Error starting server: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='SecureBank Security Lab Server')
    parser.add_argument('--port', type=int, default=8000, 
                       help='Port to run the server on (default: 8000)')
    parser.add_argument('--no-browser', action='store_true',
                       help='Don\'t automatically open browser')
    
    args = parser.parse_args()
    
    start_server(port=args.port, open_browser=not args.no_browser)

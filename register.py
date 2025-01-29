import requests
import re
import http.server
import ssl
import os
import pwd
import json

class SimpleHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Redirect all GET requests to the form.html file
        if self.path != "/form.html":
            self.send_response(302)  # HTTP status code for redirection
            self.send_header('Location', '/form.html')  # Redirect to form.html
            self.end_headers()
        else:
            # Serve the form.html file
            file_path = os.path.join(os.getcwd(), "form.html")
            if os.path.exists(file_path):
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"404 Not Found")

    def do_POST(self):
        # Get the length of the incoming data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)

        # Parse the POST data
        from urllib.parse import parse_qs
        parsed_data = parse_qs(post_data.decode('utf-8'))

        # Extract username and password
        username = parsed_data.get('username', [''])[0].replace(";","").replace("'","").replace('"',"")
        password = parsed_data.get('password', [''])[0].replace(";","").replace("'","").replace('"',"")

        # Validate username
        if len(username) < 5:
            response_message = "Username must be greater than 4 characters."
            self.send_response(400)
        elif self.check_username(username):
            response_message = f"Username {username} already exists"
            self.send_response(400)
        # Validate password
        elif self.check_password(password):
            response_message = f"Hello, {username}! Account created successfully, use Quick Connect in ATAK to join with your creds"
            self.send_response(200)
            os.system(f"java -jar /opt/tak/utils/UserManager.jar usermod -g discord -p '{password}' '{username}'")
        else:
            response_message = "Password must be at least 15 characters long, contain at least one uppercase letter, one lowercase letter, and one special character."
            self.send_response(400)

        # Respond to the client
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response_message.encode('utf-8'))

    def check_password(self, password):
        # Check password requirements
        if (len(password) >= 15 and
                re.search(r'[A-Z]', password) and  # At least one uppercase letter
                re.search(r'[a-z]', password) and  # At least one special character
                re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):  # At least one special character
            return True
        return False

    def check_username(self, username):
        url = 'https://pub.atak.zip:8443/user-management/api/list-users'
        headers = {
            'accept': '*/*'
        }
        cert_path = '/opt/tak/certs/files/admin.pem'
        key_path = '/opt/tak/certs/files/admin-decrypted.key'
    
        response = requests.get(url, headers=headers, cert=(cert_path,key_path), verify=False)
        
        # Check if the request was successful
        if response.status_code == 200:
            users = response.json()
            for user in users:
                if user['username'] == username:
                    print(f"already exists {username}")
                    return True # already exists
            return False
        else:
            print(f"Request failed with status code {response.status_code}")

def drop_privileges(user):
    """Drop root privileges by switching to a specific user."""
    if os.getuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

    # Get the UID and GID of the specified user
    try:
        user_info = pwd.getpwnam(user)
    except KeyError:
        print(f"User '{user}' not found.")
        sys.exit(1)

    uid, gid = user_info.pw_uid, user_info.pw_gid

    # Change group and user
    os.setgid(gid)
    os.setuid(uid)

    # Verify the privileges were dropped
    if os.getuid() == 0:
        print("Failed to drop privileges.")
        sys.exit(1)

    print(f"Dropped privileges to user: {user}, UID: {uid}, GID: {gid}")

def run(server_class=http.server.HTTPServer, handler_class=SimpleHTTPRequestHandler, port=443):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="certificate.crt",
                            keyfile="private.key")

    # Wrap the server's socket
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    drop_privileges("tak")

    print(f"Starting HTTPS server on port {port}...")
    httpd.serve_forever()


if __name__ == "__main__":
    run()


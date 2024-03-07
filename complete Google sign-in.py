import tkinter as tk
import webbrowser
from flask import Flask, request
import requests
import logging
import sys
from urllib.parse import unquote, urlparse, parse_qs
from threading import Thread
from werkzeug.serving import make_server

class MyApp:
    CLIENT_ID = "631768011568-2vrvoktpas2a6qqbgs1vb3ep8m0cqaue.apps.googleusercontent.com"
    CLIENT_SECRET = "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"
    REDIRECT_URI = "http://localhost:5000/callback"

    def __init__(self, root, flask_app):
        self.root = root
        self.root.title("MyApp")
        self.root.geometry("500x400")
        self.user_info = None
        self.flask_app = flask_app
        self.setup_flask_routes()

        button = tk.Button(self.root, text="Authenticate with Google",
                           command=self.initiate_google_sign_in)
        button.pack(pady=20)
        # button = tk.Button(root, text="Stop Flask App", command=self.stop_flask_app)
        # button.pack()

    def setup_flask_routes(self):
        @self.flask_app.route("/callback")
        def callback():
            auth_code = request.args.get("code")
            try:
                google_profile = self.google_authenticate(unquote(auth_code))
                if google_profile:
                    self.open_welcome_window(google_profile)
                    self.stop_flask_app()
                    return f"Authentication successful. You can close this window now."
                else:
                    return "Authentication failed. Please try again."
            except Exception as e:
                logging.error(f"Error during authentication: {e}")
                return "An error occurred during authentication. Please try again."

    def stop_flask_app(self):
        # Send a shutdown request to the Flask app
        self.flask_thread = Thread(target=self.stop_flask_thread)
        self.flask_thread.start()

    def stop_flask_thread(self):
        # This function should be executed in a separate thread
        print("Stopping Flask app...")
        self.flask_server.shutdown()

    def initiate_google_sign_in(self):
        auth_url = f"https://accounts.google.com/o/oauth2/auth?client_id={self.CLIENT_ID}&redirect_uri={self.REDIRECT_URI}&scope=profile&response_type=code"
        webbrowser.open(auth_url, new=1)
        self.root.withdraw()
        self.hide_auth_button()

    def hide_auth_button(self):
        for widget in self.root.winfo_children():
            if isinstance(widget, tk.Button) and "Authenticate with Google" in widget.cget("text"):
                widget.pack_forget()

    def get_uri_data(self):
        # Get the URI from the command line arguments
        args = sys.argv[1:]
        if args and args[0].startswith("localhost:5000/"):
            uri = args[0]
            parsed_uri = urlparse(uri)
            uri_data = parse_qs(parsed_uri.query)
            return uri_data
        return None

    def google_authenticate(self, code):
        access_token_uri = 'https://accounts.google.com/o/oauth2/token'
        params = {
            'code': code,
            'redirect_uri': self.REDIRECT_URI,
            'client_id': self.CLIENT_ID,
            'client_secret': self.CLIENT_SECRET,
            'grant_type': 'authorization_code'
        }
        headers = {'content-type': 'application/x-www-form-urlencoded'}

        try:
            with requests.session() as req:
                content = req.post(
                    access_token_uri, data=params, headers=headers)
                content.raise_for_status()
                token_data = content.json()

                user_info_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={token_data.get('access_token')}"
                content1 = req.get(user_info_url, headers=headers)
                content1.raise_for_status()
                google_profile = content1.json()
                return google_profile if 'error' not in google_profile else None
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during authentication: {e}")
            return None

    def open_welcome_window(self, google_profile):
        self.root.deiconify()
        user_id = google_profile.get("id")
        user_name = google_profile.get("name", "Unknown")

        label_text = f"Welcome to MyApp!\nID: {user_id}\nName: {user_name}"
        label = tk.Label(self.root, text=label_text)
        label.pack(pady=20)


if __name__ == "__main__":
    flask_app = Flask(__name__)
    root = tk.Tk()
    app = MyApp(root, flask_app)
    uri_data = app.get_uri_data()
    if uri_data:
        app.open_welcome_window(uri_data)

    app.flask_server = make_server('localhost', 5000, app.flask_app)
    app.flask_thread = Thread(target=app.flask_server.serve_forever)
    app.flask_thread.start()

    root.mainloop()

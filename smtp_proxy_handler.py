"""
Project: SMTP Reverse Proxy
Author: James Gibbons <jgibbons@121digital.co.uk>
Description:
    This script implements an SMTP reverse proxy using Python. It accepts incoming
    SMTP connections, authenticates clients, and forwards emails to an upstream SMTP 
    server based on the recipient's domain. The proxy extracts the SMTP credentials 
    from clients, which are then used for authenticating with the upstream SMTP server.

Requirements:
    - Python 3.7+
    - aiosmtpd (pip install aiosmtpd)

Usage:
    - Run the script to start the proxy server.
    - Configure your SMTP clients to connect to the proxy.
    - The proxy will authenticate clients and route emails based on domain.

Test Command:
    swaks --to recipient@example.com --from sender@yourdomain.com \
    --auth-user your_username --auth-password your_password \
    --server localhost:1025 --header "Subject: Test Email" --body "This is a test message."
"""

import asyncio
import smtplib
from email.message import EmailMessage
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP
from aiosmtpd.handlers import AsyncMessage

class SMTPProxyHandler(AsyncMessage):
    """
    SMTP Proxy Handler Class

    This class handles incoming SMTP requests, including authentication
    and message handling. It extracts client credentials and forwards 
    the received emails to the appropriate upstream SMTP server.
    """

    def __init__(self):
        """
        Initialize the handler with default attributes for storing
        client credentials.
        """
        self.client_username = None
        self.client_password = None

    async def handle_AUTH(self, server, session, envelope, mechanism, auth_data):
        """
        Handles the authentication process for incoming SMTP clients.
        
        Parameters:
            server (SMTP): The SMTP server instance.
            session (Session): The client session data.
            envelope (Envelope): The envelope object.
            mechanism (str): The authentication mechanism (e.g., PLAIN).
            auth_data (bytes): The authentication data provided by the client.
        
        Returns:
            str: SMTP status code for authentication success or failure.
        """
        if mechanism == "PLAIN":
            # Decode the PLAIN authentication string (format: \x00username\x00password)
            auth_str = auth_data.decode('utf-8')
            _, username, password = auth_str.split('\x00')

            # Store the extracted username and password
            self.client_username = username
            self.client_password = password
            print(f"Authenticated as {username}")
            return '235 Authentication successful'
        else:
            return '504 Unsupported authentication mechanism'

    async def handle_DATA(self, server, session, envelope):
        """
        Handles incoming email data after successful authentication.
        
        Parameters:
            server (SMTP): The SMTP server instance.
            session (Session): The client session data.
            envelope (Envelope): The envelope containing the email content.
        
        Returns:
            str: SMTP status code after handling the email.
        """
        print(f"Received email from {envelope.mail_from} to {envelope.rcpt_tos}")

        # Extract the recipient domain from the email address
        domain = envelope.rcpt_tos[0].split('@')[-1]

        # Forward the email using the credentials provided during authentication
        try:
            await forward_to_smtp_server(
                envelope.content, domain,
                self.client_username, self.client_password
            )
            return '250 Message forwarded successfully'
        except Exception as e:
            print(f"Failed to forward email: {e}")
            return f'550 Failed to forward email: {e}'


async def forward_to_smtp_server(email_content, domain, username, password):
    """
    Forwards the email content to the appropriate upstream SMTP server.
    
    Parameters:
        email_content (bytes): The raw content of the email to be forwarded.
        domain (str): The domain of the recipient.
        username (str): The client's SMTP username.
        password (str): The client's SMTP password.
    
    Raises:
        ValueError: If no upstream server is configured for the specified domain.
        Exception: If the forwarding process fails.
    """
    # Dictionary mapping domains to their respective SMTP server configurations
    domain_smtp_map = {
        'example.com': ('smtp.example.com', 587),
        'another.com': ('smtp.another.com', 587),
    }

    # Check if the domain is supported
    if domain not in domain_smtp_map:
        raise ValueError(f"No upstream server configured for domain: {domain}")

    smtp_server, smtp_port = domain_smtp_map[domain]

    print(f"Forwarding email to {smtp_server}:{smtp_port} for domain {domain}")

    # Connect to the upstream SMTP server and send the email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Upgrade the connection to TLS
        server.login(username, password)  # Authenticate using the provided credentials
        server.sendmail(username, [f'to@{domain}'], email_content)


def run_smtp_proxy(host='0.0.0.0', port=1025):
    """
    Starts the SMTP reverse proxy server.
    
    Parameters:
        host (str): The IP address to bind to (default is '0.0.0.0').
        port (int): The port to listen on (default is 1025).
    """
    handler = SMTPProxyHandler()
    controller = Controller(handler, hostname=host, port=port, auth_required=True)
    controller.start()
    print(f"SMTP reverse proxy running on {host}:{port}")


if __name__ == "__main__":
    # Run the SMTP proxy server
    run_smtp_proxy()


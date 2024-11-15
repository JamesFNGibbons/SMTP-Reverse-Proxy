# SMTP Reverse Proxy (Proof of Concept)

**Author**: James Gibbons <jgibbons@121digital.co.uk>

## Introduction

This project is a proof-of-concept **SMTP reverse proxy** implemented in Python. The proxy accepts incoming SMTP connections, authenticates clients, and forwards emails to an upstream SMTP server based on the recipient's domain. The credentials provided by the client are used to authenticate with the upstream SMTP server.

⚠️ **Disclaimer**: This project is for **educational purposes only** and is **not suitable for production use**. It lacks essential security features required in a real-world environment.

## Features

- Accepts SMTP connections from clients and authenticates using the PLAIN mechanism.
- Extracts SMTP credentials provided by clients.
- Routes emails to different upstream SMTP servers based on the recipient domain.
- Supports STARTTLS encryption when connecting to upstream SMTP servers.

## Requirements

This project requires:

- **Python 3.7+**
- **aiosmtpd** Python library

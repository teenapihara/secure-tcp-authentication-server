# Secure Multi-Client TCP Authentication Server

## Overview

This project implements a secure TCP authentication server in C with a Python client.

## Features

- Multi-client support using fork()
- TCP Socket Programming
- User Registration
- User Login
- Session Tokens
- Session Timeout
- Salted Password Hashing
- Persistent User Storage
- Audit Logging
- Account Lockout
- Rate Limiting

## Technologies

- C
- Python
- Linux
- TCP/IP Socket Programming
- GCC

## Files

server_2070.c

client_2070.py

Makefile_2070

## Compile

```bash
make -f Makefile_2070
```

## Run Server

```bash
./server_2070
```

## Run Client

```bash
python3 client_2070.py
```

## Skills Demonstrated

- Socket Programming
- Concurrent Programming
- Linux System Programming
- Network Security
- Authentication
- Process Management
- File Handling

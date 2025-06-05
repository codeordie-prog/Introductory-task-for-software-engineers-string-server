# String search server

A high-performance string search server with support for large datasets and concurrent requests.

## Prerequisites

### Windows users
1. Install WSL (Windows Subsystem for Linux):
   ```powershell
   # Open PowerShell as Administrator and run:
   wsl --install
   ```
   - This command will:
     * Enable the WSL feature
     * Install the WSL kernel
     * Set WSL 2 as default
     * Install Ubuntu as the default distribution

2. Complete WSL Setup:
   - Restart your computer when prompted
   - After restart, Ubuntu will automatically start
   - Create a new UNIX username and password when prompted
   - These credentials are separate from your Windows login

3. Verify WSL Installation:
   ```powershell
   # In PowerShell, check WSL version
   wsl --list --verbose
   
   # Expected output:
   # NAME      STATE           VERSION
   # Ubuntu    Running         2
   ```

4. Update Ubuntu:
   ```bash
   # In Ubuntu terminal
   sudo apt update && sudo apt upgrade -y
   ```

5. Install Python and required packages:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv openssl
   ```

6. Access Windows Files from WSL:
   - Windows drives are mounted under `/mnt/`
   - Example: `C:\Users\YourName\Documents` is accessible as `/mnt/c/Users/YourName/Documents`
   - Use forward slashes (/) in paths when working in WSL

7. Note: The daemon mode is not supported on native Windows, you must use WSL

### Linux/Mac users
1. Install required packages:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-pip python3-venv openssl

   # MacOS
   brew install python openssl
   ```

## Installation

1. Clone the repository to your desired location:
   ```bash
   # Windows (WSL)
   git clone https://github.com/codeordie-prog/Introductory-task-for-software-engineers-string-server.git server
   cd server

   # Linux/Mac
   git clone https://github.com/codeordie-prog/Introductory-task-for-software-engineers-string-server.git server
   cd server
   ```

2. Create and activate a virtual environment:
   ```bash
   # Create virtual environment
   python3 -m venv venv

   # Activate virtual environment
   # For Linux/WSL/Mac:
   source venv/bin/activate
   
   # Your prompt should change to show (venv)
   # Example: (venv) user@hostname:~/server$
   ```

3. Install dependencies:
   ```bash
   # Make sure you're in the virtual environment (venv)
   pip install -r requirements.txt
   ```

## Configuration

The server configuration is managed through `config/server_configurations.json`:

```json
{
    "linuxpath": "Strings/200k.txt",
    "host": "127.0.0.1",
    "port": 5555,
    "logging_level": "DEBUG",
    "workers": 4,
    "reread_on_query": false,
    "ssl_enabled": false,
    "ssl_certificate": "config/cert.pem",
    "ssl_key": "config/key.pem",
    "ssl_client_auth": false,
    "ssl_ca_certificate": "config/ca.pem",
    "ssl_verify_mode": "CERT_NONE",
    "ssl_ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS",
    "test_mode": false
}
```

### Configuration options explained:

- `linuxpath`: Path to the string file to be used (e.g., "Strings/200k.txt")
- `host`: Server host address (default: "127.0.0.1" for localhost)
- `port`: Server port number (default: 5555)
- `logging_level`: Logging verbosity ("DEBUG", "INFO", "WARNING", "ERROR")
- `workers`: Number of worker threads for handling requests (default: 4)
- `reread_on_query`:
  * `false`: Use caching for better performance
  * `true`: Read from file for each query

#### SSL configuration options:

- `ssl_enabled`: Enable/disable SSL encryption (default: false)
- `ssl_certificate`: Path to server's SSL certificate file
- `ssl_key`: Path to server's private key file
- `ssl_client_auth`: Enable/disable client certificate authentication (default: false)
- `ssl_ca_certificate`: Path to Certificate Authority (CA) certificate file
- `ssl_verify_mode`: Client certificate verification mode:
  * `CERT_NONE`: No client certificate required
  * `CERT_OPTIONAL`: Client certificate is optional but verified if provided
  * `CERT_REQUIRED`: Client certificate is required and must be valid
- `ssl_ciphers`: List of allowed cipher suites (default: "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS")
- `test_mode`: Must be set to `true` when running tests

### SSL certificate setup

# Comprehensive SSL/TLS Authentication Setup Guide

## Table of Contents
1. [SSL/TLS Fundamentals](#ssltls-fundamentals)
2. [Certificate Authority (CA) Deep Dive](#certificate-authority-ca-deep-dive)
3. [Step-by-Step Certificate Generation](#step-by-step-certificate-generation)
4. [Configuration Parameters Explained](#configuration-parameters-explained)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting and Validation](#troubleshooting-and-validation)
7. [Production Deployment Guidelines](#production-deployment-guidelines)

## SSL/TLS Fundamentals

### What Actually Happens During SSL/TLS Handshake

When a client connects to your SSL-enabled server, here's the detailed flow:

1. **Client Hello**: Client sends supported cipher suites, TLS version, random number
2. **Server Hello**: Server selects cipher suite, sends certificate chain, random number
3. **Certificate Verification**: Client validates server certificate against trusted CAs
4. **Key Exchange**: Using selected algorithm (RSA, ECDHE, DHE), both parties establish shared secret
5. **Finished Messages**: Both parties send encrypted "finished" messages to verify handshake integrity

### Authentication modes explained

Server supports three distinct authentication modes:

#### 1. No SSL (`ssl_enabled: false`)
- Plain TCP connections
- No encryption, no authentication
- Fastest performance, zero security

#### 2. Server-Only Authentication (`ssl_enabled: true, ssl_client_auth: false`)
- Server presents certificate to client
- Client verifies server identity
- Encrypted communication channel
- Client remains anonymous

#### 3. Mutual TLS/mTLS (`ssl_enabled: true, ssl_client_auth: true`)
- Both server and client present certificates
- Bidirectional authentication
- Highest security level
- Both parties' identities are cryptographically verified

## Certificate Authority (CA) deep dive

### Understanding the Trust Chain

In production environments, certificates are signed by trusted Certificate Authorities. For development/testing, we create our own CA:

```
Root CA (ca.pem)
├── Server Certificate (cert.pem) - Identifies the server
└── Client Certificate (client-cert.pem) - Identifies connecting clients
```

### Why We Need a CA

Without a CA, each certificate would need to be individually trusted. The CA acts as a trusted third party that vouches for certificate authenticity.

## Step-by-Step Certificate Generation

### Phase 1: Environment Preparation

```bash
# Create config directory if it doesn't exist
mkdir -p ./config

# Set restrictive permissions
chmod 700 ./config
```

### Phase 2: Certificate Authority Creation

```bash
# Create CA configuration file
cat > ./config/ca.conf << 'EOF'
[req]
default_bits = 4096
prompt = no
distinguished_name = ca_distinguished_name
x509_extensions = ca_extensions

[ca_distinguished_name]
C = US
ST = Development
L = Local
O = String Search Server CA
OU = Development Team
CN = String Search Server Root CA
emailAddress = admin@stringsearch.local

[ca_extensions]
basicConstraints = critical,CA:true,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

# Generate CA private key with strong encryption
openssl genrsa -aes256 -out ./config/ca-key.pem 4096

# You'll be prompted for a passphrase - REMEMBER THIS!
# This passphrase protects your CA private key

# Generate CA certificate (self-signed root)
openssl req -new -x509 -days 3650 -key ./config/ca-key.pem -out ./config/ca.pem -config ./config/ca.conf

# Verify CA certificate contents
openssl x509 -in ./config/ca.pem -text -noout

# Key points to verify:
# - Subject: Your CA distinguished name
# - Validity: 10 years from creation
# - Extensions: CA:TRUE, Key Cert Sign, CRL Sign
# - Signature Algorithm: sha256WithRSAEncryption
```

### Phase 3: Server Certificate Generation

```bash
# Create server configuration
cat > ./config/server.conf << 'EOF'
[req]
default_bits = 4096
prompt = no
distinguished_name = server_distinguished_name
req_extensions = server_req_extensions

[server_distinguished_name]
C = US
ST = Development
L = Local
O = String Search Server
OU = Server Infrastructure
CN = localhost
emailAddress = server@stringsearch.local

[server_req_extensions]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @server_alt_names

[server_alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate server private key (unencrypted for automated startup)
openssl genrsa -out ./config/key.pem 4096

# Generate Certificate Signing Request (CSR)
openssl req -new -key ./config/key.pem -out ./config/server.csr -config ./config/server.conf

# Sign server certificate with CA
openssl x509 -req -in ./config/server.csr -CA ./config/ca.pem -CAkey ./config/ca-key.pem \
    -CAcreateserial -out ./config/cert.pem -days 365 -sha256 \
    -extensions server_req_extensions -extfile ./config/server.conf

# Clean up CSR
rm ./config/server.csr

# Verify server certificate
openssl x509 -in ./config/cert.pem -text -noout
openssl verify -CAfile ./config/ca.pem ./config/cert.pem
```

### Phase 4: Client Certificate Generation

```bash
# Create client configuration
cat > ./config/client.conf << 'EOF'
[req]
default_bits = 2048
prompt = no
distinguished_name = client_distinguished_name
req_extensions = client_req_extensions

[client_distinguished_name]
C = US
ST = Development
L = Local
O = String Search Client
OU = Client Applications
CN = test-client-001
emailAddress = client@stringsearch.local

[client_req_extensions]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
EOF

# Generate client private key
openssl genrsa -out ./config/client-key.pem 2048

# Generate client CSR
openssl req -new -key ./config/client-key.pem -out ./config/client.csr -config ./config/client.conf

# Sign client certificate with CA
openssl x509 -req -in ./config/client.csr -CA ./config/ca.pem -CAkey ./config/ca-key.pem \
    -CAcreateserial -out ./config/client-cert.pem -days 365 -sha256 \
    -extensions client_req_extensions -extfile ./config/client.conf

# Clean up CSR
rm ./config/client.csr

# Verify client certificate
openssl x509 -in ./config/client-cert.pem -text -noout
openssl verify -CAfile ./config/ca.pem ./config/client-cert.pem
```

### Phase 5: File Permissions and Security

```bash
# Set appropriate permissions
chmod 400 ./config/ca-key.pem           # CA private key - most sensitive
chmod 444 ./config/ca.pem               # CA certificate - public
chmod 400 ./config/key.pem              # Server private key - sensitive
chmod 444 ./config/cert.pem             # Server certificate - public
chmod 400 ./config/client-key.pem       # Client private key - sensitive
chmod 444 ./config/client-cert.pem      # Client certificate - public

# Verify permissions
ls -la ./config/*.pem
```

## Configuration Parameters Explained

### SSL Verification Modes

The server supports three verification modes as defined in the configuration:

```json
"ssl_verify_mode": "CERT_REQUIRED"
```

1. **CERT_NONE**
   - No client certificate required
   - Basic encryption only
   - Use for public APIs where client identity isn't critical

2. **CERT_OPTIONAL**
   - Client certificate requested but not required
   - Server can implement custom logic based on certificate presence
   - Use for mixed environments (authenticated + anonymous clients)

3. **CERT_REQUIRED**
   - Client MUST present valid certificate signed by trusted CA
   - Strongest authentication - cryptographic proof of client identity
   - Use for high-security environments, service-to-service communication

### Cipher Suite Configuration

The server enforces strong cipher suites by default:

```json
"ssl_ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
```

This configuration:
- Enforces Perfect Forward Secrecy (PFS) with ECDHE/DHE
- Uses strong encryption (AES-GCM, ChaCha20)
- Excludes weak ciphers (!aNULL, !MD5, !DSS)
- Enforces minimum TLS 1.2

### Server Configuration Example

```json
{
    "ssl_enabled": true,
    "ssl_certificate": "config/cert.pem",
    "ssl_key": "config/key.pem",
    "ssl_client_auth": true,
    "ssl_ca_certificate": "config/ca.pem",
    "ssl_verify_mode": "CERT_REQUIRED",
    "ssl_ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
}
```

## Security Considerations

### Certificate Lifecycle Management

1. **Expiration Monitoring**
   ```bash
   # Check certificate expiration
   openssl x509 -in ./config/cert.pem -noout -dates
   ```

2. **Certificate Renewal**
   - Server certificate: Regenerate using Phase 3 steps
   - Client certificate: Regenerate using Phase 4 steps
   - Update server configuration if paths change

### Private Key Security

1. **Key Generation Entropy**
   ```bash
   # Ensure sufficient entropy before key generation
   cat /proc/sys/kernel/random/entropy_avail
   # Should be > 1000, ideally > 3000
   
   # If entropy is low, install haveged
   sudo apt-get install haveged
   sudo systemctl enable haveged
   ```

2. **Key Storage Security**
   ```bash
   # Use encrypted filesystems for key storage
   # Consider hardware security modules (HSMs) for production
   
   # Audit key access
   sudo auditctl -w ./config -p rwxa -k ssl-keys
   ```

### Network Security

1. **Protocol Security**
   ```python
   # In your server code, enforce strong SSL context
   import ssl
   
   context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
   context.minimum_version = ssl.TLSVersion.TLSv1_2
   context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
   context.check_hostname = False  # We're using IP addresses
   context.verify_mode = ssl.CERT_REQUIRED
   ```

## Troubleshooting and Validation

### Certificate Chain Validation

```bash
# Validate complete certificate chain
openssl verify -verbose -CAfile ./config/ca.pem ./config/cert.pem
openssl verify -verbose -CAfile ./config/ca.pem ./config/client-cert.pem

# Check certificate details
openssl x509 -in ./config/cert.pem -text -noout | grep -A5 "Subject Alternative Name"
openssl x509 -in ./config/cert.pem -text -noout | grep -A2 "Key Usage"
```

### SSL Connection Testing

```bash
# Test basic SSL connectivity
openssl s_client -connect 127.0.0.1:5555 -servername localhost

# Test with client certificate
openssl s_client -connect 127.0.0.1:5555 \
    -cert ./config/client-cert.pem \
    -key ./config/client-key.pem \
    -CAfile ./config/ca.pem \
    -verify_return_error

# Test cipher negotiation
openssl s_client -connect 127.0.0.1:5555 -cipher 'ECDHE+AESGCM'
```

### Common SSL Errors and Solutions

1. **"certificate verify failed: self signed certificate"**
   - Cause: Client doesn't trust your CA
   - Solution: Add `-CAfile ./config/ca.pem` to client commands

2. **"certificate verify failed: unable to get local issuer certificate"**
   - Cause: Incomplete certificate chain
   - Solution: Ensure CA certificate is properly configured at `./config/ca.pem`

3. **"SSL handshake failure"**
   - Cause: Cipher mismatch or protocol version incompatibility
   - Solution: Check cipher configuration and TLS versions

4. **"certificate verify failed: certificate has expired"**
   - Cause: Certificate past expiration date
   - Solution: Regenerate certificates with appropriate validity period

### Performance Monitoring

```bash
# Monitor SSL handshake performance
time openssl s_client -connect 127.0.0.1:5555 < /dev/null

# SSL session resumption testing
openssl s_client -connect 127.0.0.1:5555 -sess_out ./config/session.pem < /dev/null
openssl s_client -connect 127.0.0.1:5555 -sess_in ./config/session.pem < /dev/null
```

## Production Deployment Guidelines

### Certificate Management

1. **Use proper Certificate Authorities**
   - Let's Encrypt for public services (free)
   - Internal CA for private services
   - Commercial CAs for enterprise requirements

2. **Automated Certificate Renewal**
   ```bash
   # Example certbot setup for Let's Encrypt
   sudo certbot certonly --standalone -d yourdomain.com
   
   # Add to crontab for automatic renewal
   0 12 * * * /usr/bin/certbot renew --quiet
   ```

### Security Hardening

1. **Disable Weak Protocols**
   ```json
   {
       "ssl_protocols": ["TLSv1.2"],
       "ssl_disable_compression": true,
       "ssl_honor_cipher_order": true
   }
   ```

2. **Regular Security Audits**
   ```bash
   # Use SSL Labs' ssllabs-scan tool
   ssllabs-scan --host yourdomain.com
   
   # Or testssl.sh for detailed analysis
   ./testssl.sh 127.0.0.1:5555
   ```

### Monitoring and Alerting

1. **Certificate Expiration Alerts**
2. **SSL Handshake Failure Monitoring**
3. **Cipher Suite Usage Analytics**

## Running the server

### Method 1: Direct server start (recommended for testing)
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Start server directly (without daemon)
python3 server.py
```

### Method 2: Daemon mode (Linux/Mac/WSL only)
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Basic start
python3 daemon.py start

# With custom paths
python3 daemon.py start --pidfile /path/to/pid/file --stdout /path/to/stdout.log --stderr /path/to/stderr.log
```

### Understanding Daemon Processes

#### What is a Daemon Process?

A daemon is a background process that runs independently of any controlling terminal. Key characteristics:

- **Detached from terminal**: Survives terminal closure
- **No controlling TTY**: Cannot receive keyboard interrupts (Ctrl+C)
- **Parent process is init (PID 1)**: Orphaned and adopted by system init
- **Runs in background**: Doesn't block shell prompt
- **Persistent**: Continues running until explicitly stopped
- **System service**: Can be managed like other system services

#### Why Use Daemon Mode?

**Advantages:**
- Server persists after SSH disconnection
- Automatic process management
- Centralized logging
- Production-ready deployment model
- Resource isolation
- Clean startup/shutdown procedures

**Use Cases:**
- Production server deployment
- Long-running background services
- Automated server management
- System integration with service managers

#### The Double Fork Process

The daemon implementation uses the classic Unix double-fork technique. Here's what happens at each step:

1. **First Fork: Creating the Initial Child**
   ```python
   pid = os.fork()
   if pid > 0:
       sys.exit(0)  # Parent exits immediately
   ```
   - Creates exact copy of current process
   - Parent process exits, making child an orphan
   - Child becomes background process
   - Shell regains control immediately

2. **Session Leadership and Process Group**
   ```python
   os.setsid()
   os.umask(0)
   ```
   - Creates new session with daemon as session leader
   - Creates new process group with daemon as leader
   - Detaches from controlling terminal completely
   - Resets file creation mask for predictable permissions

3. **Second Fork: Preventing Terminal Reacquisition**
   ```python
   pid = os.fork()
   if pid > 0:
       sys.exit(0)  # First child exits
   ```
   - Ensures daemon is NOT session leader
   - Second child cannot become session leader
   - Guarantees terminal independence

4. **File Descriptor Redirection**
   ```python
   # Flush existing buffers
   sys.stdout.flush()
   sys.stderr.flush()

   # Create new file objects
   so = open(stdout_path, "a+") 
   se = open(stderr_path, "a+")

   # Redirect standard file descriptors
   os.dup2(so.fileno(), sys.stdout.fileno())
   os.dup2(se.fileno(), sys.stderr.fileno())
   ```
   - Redirects all output to log files
   - Ensures no output is lost
   - Maintains proper logging even after terminal detachment

### Daemon Installation and Management

#### Directory Structure
The daemon uses the following directory structure by default:
```
$HOME/
├── PID/
│   └── server.pid              # Process ID storage
├── logs/
│   ├── stdout.log              # Standard output capture
│   ├── stderr.log              # Error output capture
│   └── server.log              # Application-specific logs
└── config/
    └── server_configurations.json
```

#### Prerequisites
1. Ensure you have proper permissions:
   ```bash
   # Create required directories with proper permissions
   mkdir -p ~/PID ~/logs
   chmod 755 ~/PID ~/logs
   
   # Verify write permissions
   echo "test" > ~/PID/test.tmp && rm ~/PID/test.tmp
   echo "test" > ~/logs/test.tmp && rm ~/logs/test.tmp
   ```

2. Verify system requirements:
   ```bash
   # Check Python version (3.6+ required)
   python3 --version
   
   # Verify fork() system call availability
   python3 -c "import os; print('fork() available:', hasattr(os, 'fork'))"
   
   # Check signal handling capability
   python3 -c "import signal; print('Signal handling available')"
   ```

#### Daemon Management Commands

1. Start the daemon:
   ```bash
   # Basic start with default paths
   python3 daemon.py start
   
   # Start with custom paths
   python3 daemon.py start \
       --pidfile /var/run/string-search/server.pid \
       --stdout /var/log/string-search/stdout.log \
       --stderr /var/log/string-search/stderr.log
   ```

2. Check daemon status:
   ```bash
   # Check if daemon is running
   python3 daemon.py status
   
   # Verify process
   if [ -f ~/PID/server.pid ]; then
       PID=$(cat ~/PID/server.pid)
       ps -p $PID -o pid,ppid,cmd
   fi
   ```

3. Stop the daemon:
   ```bash
   # Graceful stop
   python3 daemon.py stop
   
   # Force stop if needed
   if [ -f ~/PID/server.pid ]; then
       PID=$(cat ~/PID/server.pid)
       kill -9 $PID
       rm ~/PID/server.pid
   fi
   ```

4. Restart the daemon:
   ```bash
   python3 daemon.py restart
   ```

#### Monitoring and Logs

1. View logs in real-time:
   ```bash
   # Monitor standard output
   tail -f ~/logs/stdout.log
   
   # Monitor error output
   tail -f ~/logs/stderr.log
   ```

2. Check daemon health:
   ```bash
   # Monitor process
   if [ -f ~/PID/server.pid ]; then
       PID=$(cat ~/PID/server.pid)
       ps -p $PID -o pid,ppid,pcpu,pmem,vsz,rss,etime,cmd
   fi
   
   # Check network connections
   netstat -tulpn | grep $(cat ~/PID/server.pid)
   ```

#### Systemd Integration (Optional)

For production deployments, you can integrate with systemd:

1. Create service file:
   ```bash
   sudo tee /etc/systemd/system/string-search.service << 'EOF'
   [Unit]
   Description=String Search Server
   After=network.target
   
   [Service]
   Type=forking
   User=your_username
   Group=your_group
   WorkingDirectory=/path/to/string-search-server
   Environment=VIRTUAL_ENV=/path/to/string-search-server/venv
   Environment=PATH=/path/to/string-search-server/venv/bin:$PATH
   ExecStart=/path/to/string-search-server/venv/bin/python daemon.py start
   ExecStop=/path/to/string-search-server/venv/bin/python daemon.py stop
   PIDFile=/home/your_username/PID/server.pid
   Restart=always
   RestartSec=3
   
   [Install]
   WantedBy=multi-user.target
   EOF
   ```

2. Enable and start service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable string-search.service
   sudo systemctl start string-search.service
   ```

#### Troubleshooting

1. If daemon fails to start:
   ```bash
   # Check for existing daemon
   python3 daemon.py status
   
   # Look for errors in stderr
   tail -20 ~/logs/stderr.log
   
   # Verify configuration
   python3 -c "
   import json
   try:
       with open('config/server_configurations.json') as f:
           config = json.load(f)
       print('Configuration OK')
   except Exception as e:
       print(f'Configuration error: {e}')
   "
   ```

2. If daemon starts but stops immediately:
   ```bash
   # Check recent stderr output
   tail -50 ~/logs/stderr.log
   
   # Verify data file accessibility
   python3 -c "
   import json
   with open('config/server_configurations.json') as f:
       config = json.load(f)
   import os
   file_path = config['linuxpath']
   if os.path.exists(file_path):
       if os.access(file_path, os.R_OK):
           print(f'Data file accessible: {file_path}')
       else:
           print(f'Data file not readable: {file_path}')
   else:
       print(f'Data file not found: {file_path}')
   "
   ```

### Check server status
```bash
# For daemon mode
python3 daemon.py status

# For direct mode
# Check if process is running on configured port
netstat -tulpn | grep <port>

# Find daemon processes
ps aux | grep daemon.py
```

### Stop the server
```bash
# For daemon mode
python3 daemon.py stop

# For direct mode
# Use Ctrl+C or find and kill the process
pkill -f "python3 server.py"
```

## Running tests

1. Setup for testing:
   ```bash
   # Make sure virtual environment is activated
   source venv/bin/activate

   # Install test dependencies
   pip3 install pytest
   ```

2. Configure test mode:
   - Open `config/server_configurations.json`
   - Set `"test_mode": true`

3. Run tests:
   ```bash
   # Run all tests in the testsuite directory
   python3 -m pytest testsuite/

   # Run specific test files
   python3 -m pytest testsuite/test_performance_10k_txt.py
   python3 -m pytest testsuite/test_performance_30k_txt.py
   python3 -m pytest testsuite/test_performance_250k_txt.py
   python3 -m pytest testsuite/test_performance_500k_txt.py
   python3 -m pytest testsuite/test_performance_1m_txt.py
   python3 -m pytest testsuite/test_limitation.py

 
   ```

4. Test categories:
   - Performance Tests: Measure server performance with different dataset sizes
   - Limitation Tests: Test server behavior under various load conditions
   - All tests are located in the `testsuite/` directory

## Performance testing

The server has been tested with various file sizes and configurations:

### With reread=True:
- Average execution time: <= 40ms
- Maximum concurrent requests: 500
- QPS: 241.89

### With reread=False:
- Average execution time: <= 0.5ms
- Maximum concurrent requests: 500
- QPS: 269.63

## Client usage

The client is used to measure server performance and test string search functionality.

### Prerequisites
1. Server must be running (either in direct mode or daemon mode)
2. Virtual environment must be activated
3. Server configuration must be properly set

### Running the client

1. First, ensure the server is running:
   ```bash
   # Make sure virtual environment is activated
   source venv/bin/activate

   # Start server (if not already running)
   python3 server.py
   ```

2. Basic client usage:
   ```bash
   # Make sure virtual environment is activated
   source venv/bin/activate

   # Run client with default settings
   python3 client.py
   ```

   ```
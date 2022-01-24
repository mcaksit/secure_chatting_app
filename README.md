# secure_chatting_app
A secure chatting console application via Signal Protocol.

This is a secure client-side chatting application that implements simplified version of Signal Protocol created within the scope of CS411 Cryptography course taught at Sabancı University. It utilizes Elliptic Curve Encryption (secp256k1) for key generation, Cryptographic HASH Functions (SHA3_256) and HMAC for signature generation and verification, and Diffie-Hellman for key exchange. The application Provides Forward Secrecy with the use of Ephemeral Keys. A navigation menu is provided within the code. Server URL has to be provided by the user and Key Generation steps has to be executed once prior to sending and receiving messages. User key informations are stored on a separate txt file named "client_info.txt".

import simpy
import networkx as nx
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import hashlib
import matplotlib.pyplot as plt

# Function to generate RSA key pair
def generate_rsa_key_pair():
    return RSA.generate(2048)

# Function to encrypt using RSA
def rsa_encrypt(plaintext, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    return ciphertext

# Function to decrypt using RSA
def rsa_decrypt(ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext

# Function to generate AES key
def generate_aes_key():
    return get_random_bytes(16)  # AES-128 key size

# Function to encrypt using AES
def aes_encrypt(message, key, mode):
    if mode == 'ECB':
        cipher_aes = AES.new(key, AES.MODE_ECB)
        # PKCS7 Padding for ECB mode
        message = message + (16 - len(message) % 16) * bytes([16 - len(message) % 16])

        ciphertext = cipher_aes.encrypt(message)
        return ciphertext, None, None
    elif mode == 'CBC':
        iv = get_random_bytes(16)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'GCM':
        cipher_aes = AES.new(key, AES.MODE_GCM)
    else:
        raise ValueError("Invalid AES mode")

    # For other modes (CBC, GCM), continue as before
    # PKCS7 Padding
    message += bytes([16 - len(message) % 16]) * (16 - len(message) % 16)
    ciphertext = cipher_aes.encrypt(message)

    return ciphertext, cipher_aes.iv if mode == 'CBC' else None, cipher_aes.digest() if mode == 'GCM' else None

# Function to decrypt using AES
def aes_decrypt(ciphertext, key, mode, iv=None, tag=None):
    if mode == 'ECB':
        cipher_aes = AES.new(key, AES.MODE_ECB)
        # For ECB mode, no need to process IV or tag
        return cipher_aes.decrypt(ciphertext)
    elif mode == 'CBC':
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    elif mode == 'GCM':
        cipher_aes = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
    else:
        raise ValueError("Invalid AES mode")

    decrypted_message = cipher_aes.decrypt(ciphertext)
    # PKCS7 Unpadding
    decrypted_message = decrypted_message[:-decrypted_message[-1]]

    if mode == 'GCM':
        try:
            cipher_aes.verify(tag)
        except ValueError:
            raise ValueError("GCM Mode: Authentication failed. Data may be tampered.")

    return decrypted_message

# Function to generate a zero-knowledge proof challenge
def generate_zkp_challenge():
    return get_random_bytes(16)

# Function to generate a zero-knowledge proof
def generate_zkp(secret, challenge):
    h = hashlib.sha256(secret + challenge).digest()
    return h

# Function to verify a zero-knowledge proof
def verify_zkp(secret, challenge, proof):
    expected_proof = hashlib.sha256(secret + challenge).digest()
    return proof == expected_proof

# Function to print the success rates and visualize them with Matplotlib
def print_success_rates(success_rates):
    plt.figure(figsize=(10, 6))
    for message, rate in success_rates.items():
        print(f"{message}: {rate}")
        plt.barh(message, rate)
    plt.xlabel('Success Rate')
    plt.ylabel('Messages')
    plt.title('Success Rates')
    plt.show()

# Function to simulate the transmission of encrypted packets through a network
def network_simulation(env, sender, receiver, encrypted_packet, graph):
    # Simulating network delay
    yield env.timeout(1)

    # Packet transmission from sender to receiver
    receiver.put(encrypted_packet)

    # Update the network graph to show the transmission
    graph.add_edge(sender, receiver)

# Function to simulate the transmission and measure the effectiveness of ZKP
def simulate_transmission(env, graph, use_zkp=True):
    exit_messages = {}

    # Key Generation
    system2_rsa_key_pair = generate_rsa_key_pair()
    system1_rsa_key_pair = generate_rsa_key_pair()  # Added system1_rsa_key_pair definition
    symmetric_key = generate_aes_key()

    # Key Exchange: Alice encrypts the symmetric key with Bob's public key
    encrypted_symmetric_key = rsa_encrypt(symmetric_key, system1_rsa_key_pair.publickey())

    # Zero-Knowledge Proof for Key Exchange
    challenge = generate_zkp_challenge()
    zkp_proof = generate_zkp(symmetric_key, challenge)

    # Bob verifies the zero-knowledge proof
    if verify_zkp(symmetric_key, challenge, zkp_proof):
        exit_messages["Zero-Knowledge Proof Verified: Key Exchange Successful"] = exit_messages.get("Zero-Knowledge Proof Verified: Key Exchange Successful", 0) + 1
    else:
        raise ValueError("Zero-Knowledge Proof Verification Failed: Potential Security Threat")

    # Bob decrypts the symmetric key using his private key
    decrypted_symmetric_key = rsa_decrypt(encrypted_symmetric_key, system1_rsa_key_pair)

    # Simpy processes setup
    receiver_channel = simpy.Store(env)

    # Adding nodes to the network graph
    graph.add_node("Transmission Channel")

    env.process(network_simulation(env, "System 2", receiver_channel, encrypted_symmetric_key, graph))

    # Data Packet Input: User enters the data packet to be encrypted
    user_input = input("Enter the data packet to be encrypted: ")

    try:
        # Attempt to decode the input using UTF-8
        data_packet = user_input.encode('utf-8')
    except UnicodeDecodeError:
        # If decoding fails, use a different encoding or handle the error as needed
        data_packet = user_input.encode('latin-1')

    # Choose AES mode
    aes_mode = input("Choose AES mode (ECB, CBC, GCM): ").upper()

    try:
        # Data Packet Encryption: Alice encrypts the data packet with the shared symmetric key
        encrypted_data_packet, iv, tag = aes_encrypt(data_packet, decrypted_symmetric_key, aes_mode)

        # Print Results
        print("\nOriginal Data Packet:", data_packet.decode(errors='replace'))
        print("Encrypted Data Packet:", base64.b64encode(encrypted_data_packet).decode())
        print("Decrypted Data Packet:", aes_decrypt(encrypted_data_packet, decrypted_symmetric_key, aes_mode, iv, tag).decode(errors='replace'))

        # Packet Transmission Simulation
        env.run(until=5)  # Run the simulation for a duration of 5 time units

        # Measure effectiveness of ZKP
        if use_zkp:
            exit_messages["Transmission with Zero-Knowledge Proof (ZKP) is effective."] = exit_messages.get("Transmission with Zero-Knowledge Proof (ZKP) is effective.", 0) + 1
        else:
            exit_messages["Transmission without Zero-Knowledge Proof (ZKP) is vulnerable to potential threats."] = exit_messages.get("Transmission without Zero-Knowledge Proof (ZKP) is vulnerable to potential threats.", 0) + 1

        print_success_rates(exit_messages)

    except ValueError as e:
        exit_messages[f"Error: {e}"] = exit_messages.get(f"Error: {e}", 0) + 1
        print_success_rates(exit_messages)
    except Exception as e:
        exit_messages[f"An unexpected error occurred: {e}"] = exit_messages.get(f"An unexpected error occurred: {e}", 0) + 1
        print_success_rates(exit_messages)

# Run simulation
env = simpy.Environment()
G = nx.DiGraph()
G.add_nodes_from(["System 2"])
simulate_transmission(env, G)

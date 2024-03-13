import simpy
import networkx as nx
import matplotlib.pyplot as plt
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import hashlib

# Function to generate RSA key pair
def generate_rsa_key_pair():
    return RSA.generate(2048)

# Function to decrypt using RSA
def rsa_decrypt(ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext

# Function to visualize the network graph
def visualize_network(graph):
    pos = nx.spring_layout(graph)
    nx.draw(graph, pos, with_labels=True, font_weight='bold')
    plt.show()

# Function to simulate the receiver decrypting data packets
def receiver_simulation(env, receiver, private_key, graph):
    while True:
        encrypted_packet = yield receiver.get()
        decrypted_packet = rsa_decrypt(encrypted_packet, private_key)
        print(f"Received and decrypted packet: {decrypted_packet.decode(errors='replace')} at time {env.now}")

        # Update the network graph to show the decryption
        graph.add_edge("Transmission Channel", receiver)

# Server-side functions
def server_side(env, graph):
    # Key Generation
    system1_rsa_key_pair = generate_rsa_key_pair()

    # Simpy process setup
    receiver_channel = simpy.Store(env)

    # Adding nodes to the network graph
    graph.add_node("Transmission Channel")

    env.process(receiver_simulation(env, receiver_channel, system1_rsa_key_pair, graph))

    # Run the simulation
    env.run(until=1)  # Run the simulation for a short duration to initialize the server

    # Continuously run the server
    while True:
        yield env.timeout(1)

# Visualize the initial network graph
G = nx.DiGraph()
G.add_nodes_from(["System 1"])
visualize_network(G)

# Run the server side simulation
env_server = simpy.Environment()
env_server.process(server_side(env_server, G))
env_server.run(until=5)  # Run the server for a duration of 5 time units

# Visualize the updated network graph
visualize_network(G)
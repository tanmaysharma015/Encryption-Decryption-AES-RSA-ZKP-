import psutil
import simpy
import time
import random
import matplotlib.pyplot as plt

# Function to monitor system metrics
def monitor_system(env, interval=1):
    cpu_percent = []
    memory_percent = []
    network_throughput = []

    while True:
        # Record CPU and memory utilization
        cpu_percent.append(psutil.cpu_percent())
        memory_percent.append(psutil.virtual_memory().percent)

        # Simulate network throughput (random values for demonstration)
        network_throughput.append(random.randint(100, 1000))  # Simulate network throughput

        yield env.timeout(interval)

        # Plot system metrics
        plt.figure(figsize=(10, 6))

        plt.subplot(2, 1, 1)
        plt.plot(cpu_percent, label='CPU Utilization (%)')
        plt.plot(memory_percent, label='Memory Utilization (%)')
        plt.xlabel('Time')
        plt.ylabel('Utilization')
        plt.title('CPU and Memory Utilization')
        plt.legend()

        plt.subplot(2, 1, 2)
        plt.plot(network_throughput, label='Network Throughput (Mbps)')
        plt.xlabel('Time')
        plt.ylabel('Throughput')
        plt.title('Network Throughput')
        plt.legend()

        plt.tight_layout()
        plt.show()

# Run monitor_system
env = simpy.Environment()
env.process(monitor_system(env))
env.run(until=10)  # Monitor for 10 seconds (adjust as needed)
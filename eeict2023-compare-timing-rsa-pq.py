import time
from pqcrypto.sign.dilithium4 import generate_keypair
from OpenSSL import crypto

num_runs = 10
total_elapsed_time = 0

for i in range(num_runs):
    start_time = time.time()

    sk, pk = generate_keypair()

    end_time = time.time()
    elapsed_time = (end_time - start_time) * 1000
    print(f"Dilithium key pair generated in {elapsed_time:.2f} ms.")
    total_elapsed_time += elapsed_time

avg_elapsed_time = total_elapsed_time / num_runs

print(f"Average time for generating Dilithium key pair: {avg_elapsed_time:.2f} ms")


num_runs = 10
total_elapsed_time = 0

for i in range(num_runs):
    start_time = time.time()

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 3072)

    end_time = time.time()
    elapsed_time = (end_time - start_time) * 1000
    print(f"RSA key pair generated in {elapsed_time:.2f} ms.")
    total_elapsed_time += elapsed_time

avg_elapsed_time = total_elapsed_time / num_runs

print(f"Average time for generating RSA key pair: {avg_elapsed_time:.2f} ms")
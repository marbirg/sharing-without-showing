
import random

def generate_rand_ints(n, min_v=1000, max_v=100000):
    values = []
    for it in range(n):
        values.append(random.randint(min_v, max_v))
    return values

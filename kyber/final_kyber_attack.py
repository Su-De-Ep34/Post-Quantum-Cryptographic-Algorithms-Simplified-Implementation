import numpy as np

# Parameters
n = 256  # Polynomial degree
q = 3329  # Modulus
k = 2    # Dimension of vectors/matrices

# Helper Functions
def print_vector(vec, name="Vector"):
    print(f"{name}:")
    for element in vec:
        string = ""
        for key, value in sorted(element.items(), reverse=True):
            if name == "message":
                string += f"x^{key} + "
            else:
                string += f"{value}x^{key} + "
        print(string[:-3] if string else "0")
    print()

def generate_matrix():
    A = [[{} for _ in range(k)] for _ in range(k)]
    for i in range(k):
        for j in range(k):
            element = {}
            element_size = np.random.randint(9, 15)
            power_list = np.random.choice(range(0, n), element_size, replace=False)
            coeff_list = np.random.randint(1, 100, element_size)
            for idx in range(element_size):
                element[power_list[idx]] = coeff_list[idx]
            A[i][j] = element
    return A

def generate_vector(name):
    vec = [{} for _ in range(k)]
    for i in range(k):
        element = {}
        element_size = np.random.randint(5, 10)
        power_list = np.random.choice(range(0, n), element_size, replace=False)
        coeff_list = np.random.choice([1, 0, -1 ], element_size)
        coeff_list = [(coeff + q) % q for coeff in coeff_list]
        for j in range(element_size):
            element[power_list[j]] = coeff_list[j]
        vec[i] = element
    if name != "Anonymous":
        print_vector(vec, name)
    return vec

def multiply_polynomials(a, b):
    result = {}
    for key1, value1 in a.items():
        for key2, value2 in b.items():
            new_key = (key1 + key2) % n
            new_val = (value1 * value2) % q
            if key1 + key2 >= n:
                new_val = (-new_val) % q
            if new_key in result:
                result[new_key] = (result[new_key] + new_val) % q
            else:
                result[new_key] = new_val
    return result

def add_polynomials(a, b):
    result = a.copy()
    for key, value in b.items():
        if key in result:
            result[key] = (result[key] + value) % q
        else:
            result[key] = value % q
    return result

def generate_public_key(A, s, e):
    t = [{} for _ in range(k)]
    for i in range(k):
        element = {}
        for j in range(k):
            element = add_polynomials(multiply_polynomials(A[i][j], s[j]), element)
        t[i] = add_polynomials(element, e[i])
    print_vector(t, "Vector t (Public Key)")
    return t

def encapsulate(A, t, message):
    r = generate_vector("r")
    e1 = generate_vector("e1")
    u = [{} for _ in range(k)]
    for i in range(k):
        element = {}
        for j in range(k):
            element = add_polynomials(multiply_polynomials(A[i][j], r[j]), element)
        u[i] = add_polynomials(element, e1[i])

    v = {}
    for i in range(k):
        v = add_polynomials(v, multiply_polynomials(t[i], r[i]))

    e2 = {}
    power_list = np.random.choice(range(0, n), 1, replace=False)
    coeff_list = np.random.choice(np.random.randint(100,3000), 1)
    for j in range(1):
        e2[power_list[j]] = coeff_list[j]

    v = add_polynomials(v, e2)
    v = add_polynomials(v, message)
    
    print_vector([message], "message")
    print_vector(u, "Vector u (Ciphertext Part 1)")
    print_vector([v], "Scalar v (Ciphertext Part 2)")
    return u, v

# Simple Attack to Recover Message
def attack_message(v, scaling_factor=1337, threshold=100):
    recovered_message = {}
    for key, coeff in v.items():
        multiple = round(coeff / scaling_factor)  
        estimated_message_coeff = multiple * scaling_factor
        if abs(coeff - estimated_message_coeff) < threshold:
            recovered_message[key] = multiple
        else:
            recovered_message[key] = 0
    return recovered_message

# Main Execution
print("=== Key Generation ===")
A = generate_matrix()
s = generate_vector("s")  # Secret key
e = generate_vector("e")
t = generate_public_key(A, s, e)  # Public key

print("=== Encryption ===")
message = {}
element_size = np.random.randint(1, 10)
power_list = np.random.choice(range(0, n), element_size, replace=False)
for j in range(element_size):
    message[power_list[j]] = 1  # Message bits are 1
for key in message:
    message[key] = (message[key] * 1337) % q  # Scale message

u, v = encapsulate(A, t, message)

print("=== Simple Attack to Recover Message ===")
recovered_message = attack_message(v)
print("Recovered Message (coefficients: 1 or 0):")
string = ""
for key, value in sorted(recovered_message.items(), reverse=True):
    if value != 0:
        string += f"x^{key} + "
print(string[:-3] if string else "0")
print()
print_vector([message],"message")
# Compare with original
original_powers = sorted([key for key, val in message.items() if val != 0], reverse=True)
recovered_powers = sorted([key for key, val in recovered_message.items() if val != 0], reverse=True)
original_powers = list(map(str , original_powers))
recovered_powers = list(map(str , recovered_powers))
print("Original Message Powers:", original_powers)
print("Recovered Message Powers:", recovered_powers)
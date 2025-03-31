import numpy as np
from sage.all import Matrix, ZZ, vector  # Requires SageMath

# Parameters
n = 256
q = 3329
k = 2

# --- Original Implementation Functions ---

def print_matrix(A, name="Matrix"):
    print(f"{name}:")
    for row in A:
        for element in row:
            string = ""
            for key, value in sorted(element.items(), reverse=True):
                string += f"{value}x^{key} + "
            print(string[:-3] if string else "0")
    print()

def print_vector(vec, name="Vector"):
    print(f"{name}:")
    for element in vec:
        string = ""
        for key, value in sorted(element.items(), reverse=True):
            if name == "message":
                string += f"x^{key} + "
                continue
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
    print_matrix(A, "Matrix A")
    return A

def generate_vector(name):
    vec = [{} for _ in range(k)]
    for i in range(k):
        element = {}
        element_size = np.random.randint(5, 10)
        power_list = np.random.choice(range(0, n), element_size, replace=False)
        coeff_list = np.random.choice([1, 0, -1], element_size)
        coeff_list = [(coeff + q) % q for coeff in coeff_list]
        for j in range(element_size):
            element[power_list[j]] = coeff_list[j]
        vec[i] = element
    print_vector(vec, name)
    return vec

def multiply_polynomials(a, b):
    result = {}
    for key1, value1 in a.items():
        for key2, value2 in b.items():
            new_key = key1 + key2
            new_val = (value1 * value2) % q
            if new_key >= n:
                new_key %= n
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

def sub_polynomials(a, b):
    result = a.copy()
    for key, value in b.items():
        if key in result:
            result[key] = (q + result[key] - b[key]) % q
        else:
            result[key] = (q - b[key]) % q
    return result

def encapsulate(A, t, e, s, message):
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
    coeff_list = np.random.choice([1, 2, 0], 1)
    for j in range(1):
        e2[power_list[j]] = coeff_list[j]

    v = add_polynomials(v, e2)
    v = add_polynomials(v, message)
    
    print_vector(e1, "Vector e1")
    print_vector([e2], "Scalar e2")
    print_vector([message], "message")
    print_vector(u, "Vector u (Ciphertext Part 1)")
    print_vector([v], "Scalar v (Ciphertext Part 2)")
    
    return u, v

def decapsulate(A, t, e, s, u, v, message):
    v_prime = {}
    for i in range(0, k):
        v_prime = add_polynomials(v_prime, multiply_polynomials(s[i], u[i]))
    
    print_vector([v_prime], "Scalar v' (Ciphertext Part 2)")
    
    w = sub_polynomials(v, v_prime)
    string = ""
    for key, value in sorted(w.items(), reverse=True):
        if value >= 832 and value <= 2496:
            value = 1
            string += "x^" + str(key) + " + "
    print("W (message) after encoding closest to 1664 ie q / 2 to 1 and rest to 0")
    print()
    print(string[:-3])

# --- Attack Functions ---

def poly_to_coeffs(poly, n):
    coeffs = [0] * n
    for power, coeff in poly.items():
        coeffs[power] = coeff % q
    return coeffs

def matrix_A_to_coeff_matrix(A, n, q):
    M = np.zeros((k * n, k * n), dtype=int)
    for i in range(k):
        for j in range(k):
            poly = A[i][j]
            coeffs = poly_to_coeffs(poly, n)
            for l in range(n):
                for m in range(n):
                    target = (l + m) % n
                    sign = -1 if (l + m) >= n else 1  # x^n = -1
                    M[i * n + target, j * n + m] = (M[i * n + target, j * n + m] + sign * coeffs[l]) % q
    return M

def vector_to_coeffs(t, n):
    coeffs = []
    for i in range(k):
        coeffs.extend(poly_to_coeffs(t[i], n))
    return coeffs

def attack_secret_vector(A, t):
    M_A = matrix_A_to_coeff_matrix(A, n, q)
    t_coeffs = vector_to_coeffs(t, n)

    dim = 2 * k * n  # 1024
    B = Matrix(ZZ, dim, dim)
    
    for i in range(k * n):
        B[i, i] = q
    
    for i in range(k * n):
        for j in range(k * n):
            B[k * n + i, j] = M_A[i, j]
    
    for i in range(k * n):
        B[k * n + i, k * n + i] = 1

    B_reduced = B.LLL()  # Replace with B.BKZ(block_size=20) for better results

    for row in B_reduced:
        e_part = row[:k * n]
        t_part = row[k * n:]
        norm_e = sum(x^2 for x in e_part)^0.5
        if norm_e < 50:  # Heuristic for small e
            print("Candidate e found:", e_part)
            print("Corresponding t:", t_part)
            t_minus_e = [(t_coeffs[i] - e_part[i]) % q for i in range(k * n)]
            M_A_sage = Matrix(ZZ, M_A)
            try:
                s_coeffs = M_A_sage.solve_left(vector(ZZ, t_minus_e))
                print("Recovered s coefficients:", s_coeffs)
                s_recovered = [{i: coeff for i, coeff in enumerate(s_coeffs[j * n:(j + 1) * n]) if coeff != 0} for j in range(k)]
                return s_recovered
            except ValueError:
                print("Matrix not invertible or solution invalid.")
    print("No suitable short vector found.")
    return None

# --- Main Execution ---

# Generate key pair
A = generate_matrix()
s = generate_vector("s")  # Secret key
e = generate_vector("e")
t = generate_public_key(A, s, e)  # Public key

# Generate message and encapsulate
message = {}
element_size = np.random.randint(1, 100)
power_list = np.random.choice(range(0, n), element_size, replace=False)
for j in range(element_size):
    message[power_list[j]] = 1
for key in message:
    message[key] = (message[key] * 1337) % q

u, v = encapsulate(A, t, e, s, message)
decapsulate(A, t, e, s, u, v, message)

# Perform the attack
print("\n--- Starting Attack to Recover Secret Vector s ---")
recovered_s = attack_secret_vector(A, t)
if recovered_s:
    print_vector(recovered_s, "Recovered Secret Vector s")
    print_vector(s, "Original Secret Vector s")
else:
    print("Attack failed to recover s.")
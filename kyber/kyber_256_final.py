import numpy as np

n = 256
q = 3329
k = 2  
#kyber implementation by sudeep 00:15 march 22 2025  
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
        coeff_list = np.random.choice([1,0,-1], element_size)
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

def sub_polynomials(a , b):
    result = a.copy()
    for key , value in b.items():
        if key in result:
            result[key] = (q + result[key] - b[key]) % q
        else:
            result[key] = (q-b[key]) % q
    return result


def encapsulate(A, t, e , s , message):
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
    coeff_list = np.random.choice([1,2,0], 1)
    for j in range(1):
        e2[power_list[j]] = coeff_list[j]

    # Final ciphertext computation
    v = add_polynomials(v, e2)
    v = add_polynomials(v, message)
    
    print_vector(e1 , "Vector e1")
    print_vector([e2] , "Scalar e2")
    print_vector([message] , "message")
    print_vector(u, "Vector u (Ciphertext Part 1)")
    print_vector([v], "Scalar v (Ciphertext Part 2)")
    
    return u, v

def decapsulate(A,t,e,s,u,v,message):
    v_prime = {}
    for i in range(0,k):
        v_prime = add_polynomials(v_prime , multiply_polynomials(s[i] , u[i]))
    
    print_vector([v_prime], "Scalar v' (Ciphertext Part 2)")
    
    w = {}
    string = ""
    w = sub_polynomials(v , v_prime)
    for key , value in sorted(w.items() , reverse=True):
        if value >= 832 and value <= 2496:
            value = 1
            string += "x^" + str(key) + " + "
    print("W (message) after encoding closest to 1664 ie q / 2 to 1 and rest to 0")
    print()
    print(string[:-3])
    print_vector([message],"message")


A = generate_matrix()
s = generate_vector("s")
e = generate_vector("e")
t = generate_public_key(A, s, e)

message = {}
element = message
element_size = np.random.randint(1, 100)
power_list = np.random.choice(range(0, n), element_size, replace=False)
for j in range(element_size):
    element[power_list[j]] = 1

for key , value in message.items():
    message[key] = (message[key] * 1337) % q

u, v = encapsulate(A, t, e , s , message)
#kyber implementation by sudeep 5:30am march 23 2025 
decapsulate(A,t,e,s,u,v,message)


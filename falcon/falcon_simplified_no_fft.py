import numpy as np
import sympy as sp

n = 512
q = 12289

x = sp.Symbol('x')
mod_poly = x**n + 1

def sample_discrete_gaussian(std_dev, size):
    return [int(round(np.random.normal(0, std_dev))) for _ in range(size)]

def generate_polynomials():
    sigma = 2.83
    f_coeffs = sample_discrete_gaussian(sigma, n)
    g_coeffs = sample_discrete_gaussian(sigma, n)
    return sp.Poly(f_coeffs, x, domain=sp.ZZ), sp.Poly(g_coeffs, x, domain=sp.ZZ)

def mod_inverse_poly(f, mod_poly, q):
    f_coeffs = f.all_coeffs()
    f_coeffs = [0] * (n - len(f_coeffs)) + f_coeffs
    f_coeffs = f_coeffs[-n:]
    f_mod_q = sp.Poly([coeff % q for coeff in f_coeffs], x, domain=sp.GF(q))
    mod_poly_q = sp.Poly(mod_poly, x, domain=sp.GF(q))
    f_inv = sp.invert(f_mod_q, mod_poly_q)
    f_inv_coeffs = f_inv.all_coeffs()
    f_inv_coeffs = [0] * (n - len(f_inv_coeffs)) + f_inv_coeffs
    f_inv_coeffs = [int(coeff) for coeff in f_inv_coeffs[-n:]]
    return sp.Poly(f_inv_coeffs, x, domain=sp.ZZ)

def falcon_keygen():
    while True:
        f, g = generate_polynomials()
        f_inv = mod_inverse_poly(f, mod_poly, q)
        g_coeffs = g.all_coeffs()
        g_coeffs = [0] * (n - len(g_coeffs)) + g_coeffs
        g_coeffs = g_coeffs[-n:]
        g_mod_q = sp.Poly([coeff % q for coeff in g_coeffs], x, domain=sp.GF(q))
        f_inv_mod_q = sp.Poly(f_inv.all_coeffs(), x, domain=sp.GF(q))
        mod_poly_q = sp.Poly(mod_poly, x, domain=sp.GF(q))
        h = sp.rem(g_mod_q * f_inv_mod_q, mod_poly_q, domain=sp.GF(q))
        h_coeffs = h.all_coeffs()
        h_coeffs = [0] * (n - len(h_coeffs)) + h_coeffs
        h_coeffs = [int(coeff) for coeff in h_coeffs[-n:]]
        h = sp.Poly(h_coeffs, x, domain=sp.ZZ)
        return (f, g), h
    
def sign_message(msg, private_key):
    f, g = private_key
    m_coeffs = [ord(c) % q for c in msg] + [0] * (n - len(msg))
    c = sp.Poly(m_coeffs, x, domain=sp.ZZ)
    s1 = sp.rem(f * c, mod_poly, domain=sp.ZZ)
    s1_coeffs = s1.all_coeffs()
    s1_coeffs = [0] * (n - len(s1_coeffs)) + s1_coeffs
    s1_coeffs = [coeff % q for coeff in s1_coeffs[-n:]]
    s1 = sp.Poly(s1_coeffs, x, domain=sp.ZZ)
    s2 = sp.rem(g * c, mod_poly, domain=sp.ZZ)
    s2_coeffs = s2.all_coeffs()
    s2_coeffs = [0] * (n - len(s2_coeffs)) + s2_coeffs
    s2_coeffs = [coeff % q for coeff in s2_coeffs[-n:]]
    s2 = sp.Poly(s2_coeffs, x, domain=sp.ZZ)
    return s1, s2

def verify_signature(msg, signature, public_key):
    h = public_key
    s1, s2 = signature
    h_coeffs = h.all_coeffs()
    h_coeffs = [0] * (n - len(h_coeffs)) + h_coeffs
    h_coeffs = h_coeffs[-n:]
    h_mod_q = sp.Poly(h_coeffs, x, domain=sp.GF(q))
    s1_coeffs = s1.all_coeffs()
    s1_coeffs = [0] * (n - len(s1_coeffs)) + s1_coeffs
    s1_coeffs = s1_coeffs[-n:]
    s1_mod_q = sp.Poly(s1_coeffs, x, domain=sp.GF(q))
    s2_coeffs = s2.all_coeffs()
    s2_coeffs = [0] * (n - len(s2_coeffs)) + s2_coeffs
    s2_coeffs = s2_coeffs[-n:]
    s2_mod_q = sp.Poly(s2_coeffs, x, domain=sp.GF(q))
    mod_poly_q = sp.Poly(mod_poly, x, domain=sp.GF(q))
    lhs = sp.rem(h_mod_q * s1_mod_q, mod_poly_q, domain=sp.GF(q))
    print()
    print("Verify:" , lhs)
    print()
    print("S2_mod_Q" , s2_mod_q)
    print()
    print()
    return lhs == s2_mod_q

if __name__ == "__main__":
    private_key, public_key = falcon_keygen()
    message = "SudeepIsSigningThisDocument"
    signature = sign_message(message, private_key)
    is_valid = verify_signature(message, signature, public_key)
    print("Message:", message)
    print()
    print("Signature (s1):", signature[0])
    print()
    print("Signature (s2):", signature[1])
    print()
    print("Public key (h):", public_key)
    print()
    print("Signature valid:", is_valid)
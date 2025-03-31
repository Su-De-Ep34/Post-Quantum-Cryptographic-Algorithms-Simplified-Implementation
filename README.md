# Post-Quantum-Cryptographic-Algorithms-Simplified-Implementation
Mostly NIST finalists are implemented in Python

Post-quantum cryptography (PQC) refers to cryptographic algorithms designed to be secure against attacks from quantum computers. Classical public-key cryptosystems like RSA, ECC, and DSA rely on problems (factoring large numbers, discrete logarithms, and elliptic curve logarithms) that quantum computers can solve efficiently using Shor’s Algorithm. PQC focuses on new hard mathematical problems that remain resistant even to quantum attacks.
NIST (National Institute of Standards and Technology) has been working on standardizing PQC algorithms, selecting those that provide strong security while maintaining practical efficiency.
Kyber (CRYSTALS-Kyber)
Type: Post-quantum key encapsulation mechanism (KEM)
Based on: Lattice-based cryptography (Learning With Errors - LWE problem)
Purpose: Secure key exchange, replacing traditional Diffie-Hellman and RSA key exchange methods.
Features:
Resistant to quantum attacks due to the hardness of lattice problems.
Efficient key generation and encapsulation/decapsulation processes.
Chosen as the standard for public-key encryption and key exchange in the NIST PQC standardization.
Falcon
Type: Post-quantum digital signature scheme
Based on: Lattice-based cryptography (NTRU-based problem)
Purpose: Digital signatures, an alternative to RSA and ECDSA
Features:
Smaller signature sizes compared to other PQC signature schemes.
Uses Fast Fourier Transform (FFT) for efficiency.
Provides strong security guarantees based on lattice problems.
Chosen as a standard for digital signatures by NIST.
Dilithium (CRYSTALS-Dilithium)
Type: Post-quantum digital signature scheme
Based on: Lattice-based cryptography (Learning With Errors - LWE problem)
Purpose: Digital signatures for authentication and verification.
Features:
More efficient than Falcon in terms of ease of implementation.
Slightly larger signatures than Falcon but more robust.
Chosen as the primary standard for post-quantum signatures by NIST.
Comparison of Kyber, Falcon, and Dilithium
Algorithm	Type	Security Basis	Strengths	Weaknesses
Kyber	KEM	Lattice (LWE)	Fast key exchange, low overhead	Slightly larger key sizes
Falcon	Digital Signature	Lattice (NTRU)	Smallest signature size	More complex implementation
Dilithium	Digital Signature	Lattice (LWE)	Easier implementation, robust security	Larger signatures than Falcon
Why Are These Important?
With quantum computing advancements, existing cryptographic systems will become obsolete. These post-quantum cryptosystems provide a secure alternative for future-proofing encryption and authentication mechanisms.

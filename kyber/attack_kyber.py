import numpy as np

# Define parameters
n = 4    # Polynomial degree (x^4 + 1)
q = 3329 # Modulus

# Define the secret vector s with small integer coefficients
s = np.array([1, 2, 0, 1], dtype=int)

# Define multiplication matrices in the ring Zq[x]/(x^4 + 1) as float for least squares
# M_1: Multiplication by 1 (identity matrix)
M_1 = np.array([[1, 0, 0, 0],
                [0, 1, 0, 0],
                [0, 0, 1, 0],
                [0, 0, 0, 1]], dtype=float)

# M_x: Multiplication by x (shifts coefficients, x^4 = -1)
M_x = np.array([[ 0, 0, 0, -1],
                [ 1, 0, 0,  0],
                [ 0, 1, 0,  0],
                [ 0, 0, 1,  0]], dtype=float)

# M_x2: Multiplication by x^200
M_x2 = np.array([[ 0, 0, -1,  0],
                 [ 0, 0,  0, -1],
                 [ 1, 0,  0,  0],
                 [ 0, 1,  0,  0]], dtype=float)

# M_x3: Multiplication by x^3
M_x3 = np.array([[ 0, -1,  0,  0],
                 [ 0,  0, -1,  0],
                 [ 0,  0,  0, -1],
                 [ 1,  0,  0,  0]], dtype=float)

# List of multiplication matrices
matrices = [M_1, M_x, M_x2, M_x3]

# Set random seed for reproducibility
np.random.seed(42)

# Generate observations
v_list = []
for M in matrices:
    # Generate small noise vector e2 with coefficients in {-1, 0, 1}
    e2 = np.random.choice([-1, 0, 1], size=n)
    # Compute v_true = M * s + e2 (as float)
    v_true = np.dot(M, s.astype(float)) + e2
    # Apply modular reduction to simulate observed values
    v_observed = np.mod(v_true, q)
    # Center v_observed to the range [-q/2, q/2]
    v_centered = np.where(v_observed > q / 2, v_observed - q, v_observed)
    v_list.append(v_centered)

# Stack all centered observation vectors into a single 16x1 vector
v_centered = np.concatenate(v_list)

# Stack all multiplication matrices into a single 16x4 matrix A
A = np.vstack(matrices)

# Solve for s using least squares method
s_estimated, residuals, rank, singular = np.linalg.lstsq(A, v_centered, rcond=None)
# Round the estimated s to the nearest integers
s_estimated = np.round(s_estimated).astype(int)

# Print the results
print("Original secret s:", s)
print("Estimated secret s:", s_estimated)
print("Attack successful:", np.array_equal(s, s_estimated))
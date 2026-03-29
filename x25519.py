#!/usr/bin/env python3
"""x25519 - Curve25519 Diffie-Hellman key exchange."""
import sys, json

P = 2**255 - 19
A24 = 121665

def mod_inv(a, p=P):
    return pow(a, p-2, p)

def cswap(swap, x2, x3):
    dummy = swap * (x2 ^ x3)
    return x2 ^ dummy, x3 ^ dummy

def x25519_scalar_mult(k, u):
    x_1 = u; x_2 = 1; z_2 = 0; x_3 = u; z_3 = 1; swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t
        A = (x_2 + z_2) % P; AA = (A * A) % P
        B = (x_2 - z_2) % P; BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P; D = (x_3 - z_3) % P
        DA = (D * A) % P; CB = (C * B) % P
        x_3 = pow(DA + CB, 2, P)
        z_3 = (x_1 * pow(DA - CB, 2, P)) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + A24 * E)) % P
    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    return (x_2 * mod_inv(z_2)) % P

def clamp(k):
    k_bytes = bytearray(k.to_bytes(32, 'little'))
    k_bytes[0] &= 248; k_bytes[31] &= 127; k_bytes[31] |= 64
    return int.from_bytes(k_bytes, 'little')

def main():
    print("X25519 key exchange demo\n")
    BASE = 9
    alice_priv = clamp(int.from_bytes(bytes(range(32)), 'little'))
    bob_priv = clamp(int.from_bytes(bytes(range(32, 64)), 'little'))
    alice_pub = x25519_scalar_mult(alice_priv, BASE)
    bob_pub = x25519_scalar_mult(bob_priv, BASE)
    shared_a = x25519_scalar_mult(alice_priv, bob_pub)
    shared_b = x25519_scalar_mult(bob_priv, alice_pub)
    print(f"  Alice pub: {alice_pub:064x}")
    print(f"  Bob pub:   {bob_pub:064x}")
    print(f"  Shared A:  {shared_a:064x}")
    print(f"  Shared B:  {shared_b:064x}")
    print(f"  Match: {'✓' if shared_a == shared_b else '✗'}")

if __name__ == "__main__":
    main()

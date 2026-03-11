#!/usr/bin/env python3
"""x25519 - X25519 Diffie-Hellman key exchange (Curve25519, RFC 7748).

Usage: python x25519.py [--demo]
"""
import os

p = 2**255 - 19
a24 = 121665

def clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)

def decode_u(u):
    u = bytearray(u)
    u[31] &= 127
    return int.from_bytes(u, 'little')

def x25519(k_bytes, u_bytes):
    k = int.from_bytes(clamp(k_bytes), 'little')
    u = decode_u(u_bytes)
    
    # RFC 7748 Montgomery ladder
    x_1 = u
    x_2 = 1; z_2 = 0
    x_3 = u; z_3 = 1
    
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        # cswap
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t
        
        A = (x_2 + z_2) % p
        AA = (A * A) % p
        B = (x_2 - z_2) % p
        BB = (B * B) % p
        E = (AA - BB) % p
        C = (x_3 + z_3) % p
        D = (x_3 - z_3) % p
        DA = (D * A) % p
        CB = (C * B) % p
        x_3 = ((DA + CB) * (DA + CB)) % p
        z_3 = (x_1 * ((DA - CB) * (DA - CB) % p)) % p
        x_2 = (AA * BB) % p
        z_2 = (E * ((AA + (a24 * E) % p) % p)) % p
    
    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2
    
    return ((x_2 * pow(z_2, p-2, p)) % p).to_bytes(32, 'little')

def main():
    print("=== X25519 (RFC 7748) ===\n")
    
    # Iterated test: start with k=u=9
    bp = b'\x09' + b'\x00' * 31
    k = bp; u = bp
    r = x25519(k, u)
    exp1 = '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079'
    print(f"k=u=9, 1 iter: {'✓' if r.hex()==exp1 else '✗'} {r.hex()[:40]}...")
    
    # Test vectors
    k1 = bytes.fromhex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4')
    u1 = bytes.fromhex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
    e1 = 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'
    r1 = x25519(k1, u1)
    print(f"Vector 1: {'✓' if r1.hex()==e1 else '✗'} {r1.hex()[:40]}...")
    
    # Key exchange
    print("\nKey exchange:")
    a_priv, b_priv = os.urandom(32), os.urandom(32)
    a_pub = x25519(a_priv, bp); b_pub = x25519(b_priv, bp)
    print(f"  Shared: {'✓' if x25519(a_priv,b_pub)==x25519(b_priv,a_pub) else '✗'}")

if __name__ == "__main__":
    main()

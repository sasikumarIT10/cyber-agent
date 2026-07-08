"""Generate self-signed TLS certificates for the Cybersecurity AI Agent.

Usage:
    python generate_certs.py
    python generate_certs.py --ip 192.168.1.100 --days 365

This creates certs/server.crt and certs/server.key for HTTPS.
For production, use proper CA-signed certificates instead.
"""

import argparse
import datetime
import os
import socket
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("[ERROR] 'cryptography' package not installed.")
    print("  Run: pip install cryptography")
    exit(1)


def generate_self_signed_cert(ip_addresses=None, days=365, output_dir=None):
    """Generate a self-signed certificate with SAN entries."""
    if output_dir is None:
        output_dir = Path(__file__).parent / "certs"
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate RSA key (2048-bit)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Build subject
    hostname = socket.gethostname()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberAgent"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])

    # Build SAN (Subject Alternative Names)
    san_entries = [
        x509.DNSName("localhost"),
        x509.DNSName(hostname),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    if ip_addresses:
        for ip_str in ip_addresses:
            try:
                san_entries.append(x509.IPAddress(ipaddress.IPv4Address(ip_str)))
            except Exception:
                print(f"  [WARN] Skipping invalid IP: {ip_str}")

    # Try to detect the machine's LAN IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        san_entries.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
        print(f"  Auto-detected LAN IP: {local_ip}")
    except Exception:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .sign(key, hashes.SHA256())
    )

    # Write key
    key_path = output_dir / "server.key"
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Write cert
    cert_path = output_dir / "server.crt"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"\n  TLS Certificate Generated!")
    print(f"  Certificate: {cert_path}")
    print(f"  Private Key: {key_path}")
    print(f"  Valid for:   {days} days")
    print(f"  Hostname:    {hostname}")
    print(f"\n  SANs: {', '.join(str(s.value) for s in san_entries)}")
    print(f"\n  [!] This is a SELF-SIGNED certificate.")
    print(f"  Clients will see a browser warning. For production, use a proper CA.")
    print()

    return str(cert_path), str(key_path)


if __name__ == "__main__":
    import ipaddress as ipaddress

    parser = argparse.ArgumentParser(description="Generate self-signed TLS certs")
    parser.add_argument("--ip", nargs="*", help="Additional IP addresses for SAN")
    parser.add_argument("--days", type=int, default=365, help="Certificate validity (days)")
    args = parser.parse_args()

    generate_self_signed_cert(ip_addresses=args.ip, days=args.days)

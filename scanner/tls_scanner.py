import socket
import ssl

DEFAULT_TIMEOUT = 10


def get_certificate(domain, port=443, timeout=DEFAULT_TIMEOUT):
    """connect to domain over TLS and return its leaf certificate.
       verification disabled; parsing happens later
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            der = ssock.getpeercert(binary_form=True)
            try:
                parsed = ssock.getpeercert()
            except ValueError:
                parsed = None

    return {"der": der, "parsed": parsed}


if __name__ == "__main__":
    cert = get_certificate("google.com")
    print(f"DER bytes: {len(cert['der'])}")
    print(cert["parsed"])

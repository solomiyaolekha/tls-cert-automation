import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509.oid import NameOID

@dataclass
class CertData:
    domain: str
    cn: str
    san: list
    issuer: dict
    valid_to: datetime
    days_left: int
    status: str

    def __lt__(self, other):
        # Для heapq: чим менше днів, тим вищий пріоритет
        return self.days_left < other.days_left

class CertificateScanner:
    def __init__(self, threshold=30):
        self.threshold = threshold

class HttpsCertificateScanner(CertificateScanner):
    def get_info(self, hostname):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_der)
                    
                    expiry = cert.not_valid_after_utc
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    
                    try:
                        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        san = ext.value.get_values_for_type(x509.DNSName)
                    except:
                        san = []

                    return CertData(
                        domain=hostname,
                        cn=cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                        san=san,
                        issuer={"common_name": cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value},
                        valid_to=expiry,
                        days_left=days_left,
                        status="expiring_soon" if days_left < self.threshold else "ok"
                    )
        except Exception as e:
            raise Exception(f"Connection error for {hostname}: {str(e)}")
import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class CsrGenerator:
    def __init__(self, key_path="private.key"):
        self.__key_path = key_path

    def __get_private_key(self):
        # Інкапсуляція: приватний метод для отримання ключа
        if os.path.exists(self.__key_path):
            with open(self.__key_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.__key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        return key

    def generate_csr(self, common_name):
        key = self.__get_private_key()
        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        csr = builder.sign(key, hashes.SHA256())
        csr_path = f"{common_name}.csr"
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        return csr_path

class CertificateSigner:
    def __init__(self):
        self.__hash_algorithm = hashes.SHA256()

    def self_sign_csr(self, csr_path, key_path, output_cert_path):
        with open(csr_path, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read())
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        builder = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            csr.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )

        for extension in csr.extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)

        certificate = builder.sign(private_key, self.__hash_algorithm)
        with open(output_cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
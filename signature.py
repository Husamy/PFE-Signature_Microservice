from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
from cryptography.hazmat.backends import default_backend
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import os

input_file_path= 'sample.pdf'
signed_path = 'document_signed.txt'
output_file_path = 'signed_sample.pdf'
private_key_path='private_key.pem'
certificate_path='certificate.pem'

def genarate():
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Create a self-signed certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Tunis"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lac 2"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigitalBerry"),
        x509.NameAttribute(NameOID.COMMON_NAME, "DigiCertif.fr"),
    ]))
    
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Nabeul"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kelibia"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MakeMoney"),
        x509.NameAttribute(NameOID.COMMON_NAME, "dolar.com"),
    ]))
    
    
    
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    cert = builder.sign(private_key, hashes.SHA256())

    # Save the private key to a file
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        print("Private key saved to private_key.pem")

    # Save the public key to a file
    with open('public_key.pem', 'wb') as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        print("Public key saved to public_key.pem")

    # Save the certificate to a file
    with open('certificate.pem', 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        print("Certificate saved to certificate.pem")
        
        
import io
import PyPDF2
from PyPDF2 import PdfFileWriter, PdfFileReader
from PyPDF2.generic import NameObject, createStringObject
from PyPDF2.utils import b_
from io import BytesIO
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from PyPDF2 import PdfFileReader, PdfFileWriter
from PyPDF2.generic import NameObject, createStringObject
from PyPDF4.generic import NameObject, createStringObject, ArrayObject

def sign_pdf(input_file_path, output_file_path, private_key_path, certificate_path):
    # Load the private key
    with open(private_key_path, 'rb') as f:
        private_key_data = f.read()
    private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())

    # Load the certificate
    with open(certificate_path, 'rb') as f:
        certificate_data = f.read()
    certificate = load_pem_x509_certificate(certificate_data, backend=default_backend())

    # Load the input PDF into memory
    with open(input_file_path, 'rb') as f:
        pdf_data = BytesIO(f.read())

    # Create a PDF writer
    pdf_writer = PdfFileWriter()

    # Read all pages of the input PDF
    pdf_reader = PdfFileReader(pdf_data)
    for i in range(pdf_reader.getNumPages()):
        page = pdf_reader.getPage(i)

        # Create the signature object
        sig_object = PyPDF2.generic.DictionaryObject()
        sig_object.update({
            NameObject('/Type'): NameObject('/Sig'),
            NameObject('/Filter'): NameObject('/Adobe.PPKLite'),
            NameObject('/SubFilter'): NameObject('/adbe.pkcs7.detached'),
            NameObject('/Name'): createStringObject('DigitalBerry'),
            NameObject('/Reason'): createStringObject('To prove a concept'),
            NameObject('/Location'): createStringObject('Canada'),
            NameObject('/M'): createStringObject(datetime.datetime.utcnow().strftime('D:%Y%m%d%H%M%S%Z')),
        })

        # Create the signature field
        sig_field = sig_object
        sig_field.update({
            NameObject('/ByteRange'): ArrayObject([0, 0, 0, 0]),
            NameObject('/Contents'): createStringObject('')
        })

        # Convert the signature field to a bytes object
        sig_field_bytes = sig_field.__repr__().encode('latin-1')

        # Compute the message digest
        md = hashes.Hash(hashes.SHA256(), backend=default_backend())
        md.update(sig_field_bytes)
        digest = md.finalize()

        # Sign the digest
        signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Embed the signature into the signature field
        sig_field.update({
            NameObject('/ByteRange'): ArrayObject([0, len(sig_field_bytes), len(sig_field_bytes) + len(signature), len(sig_field_bytes) + len(signature)]),
            NameObject('/Contents'): createStringObject(signature),
        })

        # Add the signature field to the page
        page['/Annots'] = ArrayObject([sig_field])

        # Add the page to the PDF writer
        pdf_writer.addPage(page)

    # Write the signed PDF to the output file
    with open(output_file_path, 'wb') as f:
        pdf_writer.write(f)
        
genarate()
sign_pdf(input_file_path=input_file_path,output_file_path=output_file_path,private_key_path=private_key_path,certificate_path=certificate_path)
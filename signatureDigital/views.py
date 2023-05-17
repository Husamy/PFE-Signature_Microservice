import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import os
from cryptography.hazmat.backends import default_backend
import datetime
from rest_framework import generics
from .serializers import DocumentSignSerializer
from .models import signedDocument
from django.core.files.uploadedfile import InMemoryUploadedFile
import base64
from rest_framework import generics, status
from rest_framework.response import Response
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from django.shortcuts import get_object_or_404
import requests
import json
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from rest_framework.permissions import IsAuthenticated
from django.http import HttpRequest




class SignedDocumentList(generics.ListCreateAPIView):
    queryset = signedDocument.objects.all()
    serializer_class = DocumentSignSerializer
    permission_classes=[IsAuthenticated,]

    def perform_create(self, serializer):
        
        
        host_ip = os.environ.get('HOST_IP')
        token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        headers = {'Authorization': f'Bearer {token}'}
        keys_url = 'http://'+str(host_ip)+':8002/api/keys/'
        response = requests.get(url=keys_url, headers=headers)
        data = json.loads(response.content.decode('utf-8'))
        private_key = load_pem_private_key(data[0]['privateKey'].encode(), password=None)
        print(private_key)
        public_key = load_pem_public_key(data[0]['publicKey'].encode())

                # Create a self-signed certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "TN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "TN"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Heberge LAC II"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DigitalBerry"),
            x509.NameAttribute(NameOID.COMMON_NAME, "berrycert.fr"),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.request.data.get('country_name')),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.request.data.get('state_or_province_name')),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.request.data.get('locality_name')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.request.data.get('name')),
            x509.NameAttribute(NameOID.COMMON_NAME, self.request.data.get('common_name')),
        ]))
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False,
        )
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.datetime.utcnow())
        builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        cert = builder.sign(private_key, hashes.SHA256(), default_backend())
        
        
        
        doc_url = 'http://'+str(host_ip)+':8003/documents/doc/content/' + str(self.request.data.get('document_id')) 
        response = requests.get(url=doc_url, headers=headers)
        
        data_doc = response.content
        # Set the public key, private key, and certificate fields in the serializer
        signature = private_key.sign(
            data_doc,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        serializer.validated_data['cert'] = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        # Get the uploaded file object and read its contents
        serializer.validated_data['document_id'] = self.request.data.get('document_id')
        serializer.validated_data['owner'] = self.request.data.get('owner')
        serializer.validated_data['user_id'] = self.request.data.get('user_id')
        serializer.validated_data['signature'] = base64.b64encode(signature).decode('utf-8')
        #serializer.validated_data['signature'] = base64.b64encode(signature).decode('utf-8')
        
        # Save the serializer
        serializer.save()
        



import base64
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_pem_x509_certificate



class VerifySignatureView(generics.CreateAPIView):
    
    
    def create(self, request, *args, **kwargs):
        
        host_ip = os.environ.get('HOST_IP')
        token = self.request.META.get('HTTP_AUTHORIZATION', '').split(' ')[1]
        headers = {'Authorization': f'Bearer {token}'}
        
        doc_url = 'http://'+str(host_ip)+':8003/documents/doc/content/' + str(self.request.data.get('document_id'))
        responseDoc = requests.get(url=doc_url, headers=headers)
        
        # Retrieve document_id and actual document data from request data
        document_id = request.data.get('document_id')
        actual_document = responseDoc.content
        # Retrieve signed document object from database
        signed_doc = get_object_or_404(signedDocument, document_id=document_id)

        # Extract public key, certificate, and signature from signed document object
        cert = signed_doc.cert.encode('utf-8')
        signature = base64.b64decode(signed_doc.signature.encode('utf-8'))


        # Verify certificate
        try:
            cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
            public_key = cert_obj.public_key()
            print(public_key)
            cert_obj.public_key().verify(
                signature,
                actual_document,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except:
            return Response({'message': 'Certificate verification failed'}, status=status.HTTP_400_BAD_REQUEST)

        # Verify certificate expiration date
        now = datetime.datetime.utcnow()
        if now < cert_obj.not_valid_before or now > cert_obj.not_valid_after:
            return Response({'message': 'Certificate has expired or is not yet valid'}, status=status.HTTP_400_BAD_REQUEST)

        # Verify signature
        
        print("Verifying Signature")
        h = SHA256.new(actual_document)
        rsa = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        rsa = RSA.import_key(rsa)
        signer = PKCS1_v1_5.new(rsa)
        rsp = {'message': 'Signature verification successful'} if (signer.verify(h, signature)) else {'message': 'Signature verification failed'}
        print(rsp)
        

        return Response(rsp, status=status.HTTP_200_OK)


from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
        

class GetCert(generics.RetrieveAPIView):
    queryset = signedDocument.objects.all()
    serializer_class = DocumentSignSerializer
    permission_classes = [IsAuthenticated]
    lookup_url_kwarg = 'document_id'
    
    def get(self, request, *args, **kwargs):
        instance = self.get_object()  # Retrieve the object instance
        cert = load_pem_x509_certificate(instance.cert.encode('utf-8'), default_backend())
        instance.save()
        
        serializer = self.get_serializer(instance)
        
        
        return Response({
            'Model': str(serializer.data),
            'serial_number': str(cert.serial_number),
            'subject': str(cert.subject),
            'issuer': str(cert.issuer),
            'not_valid_before': str(cert.not_valid_before),
            'not_valid_after': str(cert.not_valid_after),
        })

        


















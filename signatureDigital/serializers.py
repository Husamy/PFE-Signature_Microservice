from rest_framework import serializers
from .models import signedDocument
import os
import json
import requests
import datetime

class DocumentSignSerializer(serializers.ModelSerializer):
    expirationDate=serializers.ReadOnlyField()
    issueDate=serializers.ReadOnlyField()
    cert = serializers.ReadOnlyField()
    signature = serializers.ReadOnlyField()
    document_id = serializers.ReadOnlyField()
    user_id = serializers.ReadOnlyField()
    owner = serializers.ReadOnlyField()
    
    
    class Meta:
        model = signedDocument
        fields = ('id', 'document_id', 'user_id',  'owner', 'expirationDate', 'issueDate', 'signature','cert')
    


    def create(self, validated_data):
        validated_data['expirationDate'] = datetime.datetime.now().date() + datetime.timedelta(days=30)
        validated_data['issueDate'] = datetime.datetime.now().date()
        return super().create(validated_data)
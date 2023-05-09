from django.db import models

# Create your models here.

    
class signedDocument(models.Model):
    document_id = models.IntegerField(unique=True)
    owner = models.EmailField(max_length=30)
    user_id = models.IntegerField(max_length=10)
    issueDate = models.DateField()
    expirationDate = models.DateField()
    cert = models.CharField()
    signature = models.CharField()

    def __str__(self) -> str:
        return str(self.id)
    




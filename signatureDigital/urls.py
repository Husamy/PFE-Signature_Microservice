from django.urls import path
from .views import SignedDocumentList , VerifySignatureView, GetCert


urlpatterns = [
    path("sign/", SignedDocumentList.as_view()),
    path('verify/', VerifySignatureView.as_view()),
    path('getCert/<int:document_id>', GetCert.as_view()),
]
from django.db import models
from django.contrib.auth.models import User
import numpy as np
import json
from .aes import SimpleEncryptor
import base64


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15, blank=True)
    cnic = models.CharField(max_length=15, blank=True)
    rsa_public_key = models.TextField(blank=True)  
    rsa_private_key = models.TextField(blank=True) 

    def set_rsa_keys(self, public_key, private_key):
        """Store RSA keys: public key as JSON, private key encrypted with AES."""
        encryptor = SimpleEncryptor()
     
        private_key_json = json.dumps(private_key)
   
        encrypted_private_key = encryptor.encrypt(private_key_json)
     
        encrypted_private_key_b64 = base64.b64encode(encrypted_private_key).decode()
        
        self.rsa_public_key = json.dumps(public_key)
        self.rsa_private_key = encrypted_private_key_b64
        self.save()

    def get_rsa_public_key(self):
        """Retrieve RSA public key as tuple."""
        return tuple(json.loads(self.rsa_public_key))

    def get_rsa_private_key(self):
        """Retrieve and decrypt RSA private key as tuple."""
        encryptor = SimpleEncryptor()
  
        encrypted_private_key = base64.b64decode(self.rsa_private_key.encode())
    
        private_key_json = encryptor.decrypt(encrypted_private_key)
    
       
        return tuple(json.loads(private_key_json))

    def __str__(self):
        return self.user.username

# 2. Chat History
class ChatHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    query = models.TextField()
    response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

# 3. Medical Document
class MedicalDocument(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    pdf_file = models.FileField(upload_to='medical_pdfs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.pdf_file.name}"

# 4. Document Embedding
class DocumentEmbedding(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False, default=1)
    document = models.ForeignKey(MedicalDocument, on_delete=models.CASCADE, null=False)
    text_chunk = models.TextField()  
    embedding = models.TextField() 
    created_at = models.DateTimeField(auto_now_add=True)

    def set_embedding(self, embedding_vector):
        if not isinstance(embedding_vector, list):
            raise ValueError("Embedding vector must be a list.")
        self.embedding = json.dumps(embedding_vector)
        self.save()

    def get_embedding(self):
        """Convert JSON string to numpy array."""
        return np.array(json.loads(self.embedding))

    def __str__(self):
        return f"Document uploaded by {self.user.username}"
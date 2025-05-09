from django.db import models
from django.contrib.auth.models import User
import numpy as np
import json
from .aes import SimpleEncryptor
import base64

# 1. User Profile
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15, blank=True)
    cnic = models.CharField(max_length=15, blank=True)
    rsa_public_key = models.TextField(blank=True)  # Store public key as JSON string
    rsa_private_key = models.TextField(blank=True) # Store AES-encrypted private key as JSON string

    def set_rsa_keys(self, public_key, private_key):
        """Store RSA keys: public key as JSON, private key encrypted with AES."""
        encryptor = SimpleEncryptor()
        # Convert private_key to JSON string before encryption
        private_key_json = json.dumps(private_key)
        # Encrypt the private key
        encrypted_private_key = encryptor.encrypt(private_key_json)
        # Encode encrypted bytes to base64 for storage
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
        # Decode base64 to get encrypted bytes
        encrypted_private_key = base64.b64decode(self.rsa_private_key.encode())
        # Decrypt to get JSON string
        private_key_json = encryptor.decrypt(encrypted_private_key)
        # Parse JSON to get 
       
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
    text_chunk = models.TextField()  # Yeh extracted text hoga
    embedding = models.TextField()   # Embedding ko JSON string ke form me save karenge
    created_at = models.DateTimeField(auto_now_add=True)

    def set_embedding(self, embedding_vector):
        if not isinstance(embedding_vector, list):
            raise ValueError("Embedding vector must be a list.")
        
        # Directly store the embedding as a JSON string without calling tolist()
        self.embedding = json.dumps(embedding_vector)
        self.save()

    def get_embedding(self):
        """Convert JSON string to numpy array."""
        return np.array(json.loads(self.embedding))

    def __str__(self):
        return f"Document uploaded by {self.user.username}"
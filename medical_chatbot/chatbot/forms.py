from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile
from .hash import hash_password
from .rsa import rsa_encrypt, rsa_decrypt, generate_keys
import logging
import json

logger = logging.getLogger(__name__)

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    phone_number = forms.CharField(max_length=11, required=False)
    cnic = forms.CharField(max_length=13, required=False)

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', 'phone_number', 'cnic')

    def clean_username(self):
        username = self.cleaned_data['username']
        # Check for username uniqueness by decrypting existing usernames
        for user in User.objects.select_related('userprofile').all():
            try:
                profile = user.userprofile
                private_key = profile.get_rsa_private_key()  # Decrypts AES-encrypted private key
                decrypted_username = rsa_decrypt(user.username, private_key)
                if decrypted_username == username:
                    logger.warning(f"Username {username} already exists")
                    raise forms.ValidationError("User already exists. Please choose a different username.")
            except UserProfile.DoesNotExist:
                continue
            except Exception as e:
                logger.warning(f"Error decrypting username for user {user.id}: {str(e)}")
                continue
        return username

    def clean_phone_number(self):
        phone_number = self.cleaned_data['phone_number']
        if phone_number:  # Only validate if phone_number is provided
            if not phone_number.isdigit():
                raise forms.ValidationError("Phone number must contain only digits.")
            if len(phone_number) != 11:
                raise forms.ValidationError("Phone number must be exactly 11 digits.")
        return phone_number

    def clean_cnic(self):
        cnic = self.cleaned_data['cnic']
        if cnic:  
            if not cnic.isdigit():
                raise forms.ValidationError("CNIC must contain only digits.")
            if len(cnic) != 13:
                raise forms.ValidationError("CNIC must be exactly 13 digits.")
        return cnic

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
       
        user.password = hash_password(self.cleaned_data['password1'])
   
        try:
            public_key, private_key = generate_keys()
            user.username = rsa_encrypt(self.cleaned_data['username'], public_key, use_nonce=False)
            logger.info(f"Encrypted username: {user.username}")
        except Exception as e:
            logger.error(f"Username encryption failed: {str(e)}")
            raise
        if commit:
            user.save()
            try:
       
                encrypted_phone = rsa_encrypt(self.cleaned_data['phone_number'], public_key, use_nonce=True) if self.cleaned_data['phone_number'] else ''
                encrypted_cnic = rsa_encrypt(self.cleaned_data['cnic'], public_key, use_nonce=True) if self.cleaned_data['cnic'] else ''
                logger.info(f"Encrypted phone_number: {encrypted_phone}, cnic: {encrypted_cnic}")
                user_profile = UserProfile.objects.create(
                    user=user,
                    phone_number=encrypted_phone,
                    cnic=encrypted_cnic
                )
            
                user_profile.set_rsa_keys(public_key, private_key)
                logger.info(f"RSA keys generated and stored for user: {user.username}")
            except Exception as e:
                logger.error(f"UserProfile creation failed: {str(e)}")
            
                user.delete()
                raise
        return user, public_key, private_key

class OTPVerificationForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True, label="Enter OTP")
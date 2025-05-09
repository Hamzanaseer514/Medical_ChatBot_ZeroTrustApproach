from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.contrib.auth.models import User
from .models import MedicalDocument, ChatHistory, UserProfile, DocumentEmbedding
from .forms import CustomUserCreationForm, OTPVerificationForm
from .utils import initialize_llm, create_vector_db, load_vector_db, setup_qa_chain
from .utils import generate_embedding
from .hash import hash_password, verify_password
import os
import random
import logging
from django.core.mail import send_mail
from django.conf import settings
import time
from .rsa import rsa_encrypt, rsa_decrypt, generate_keys
from .aes import SimpleEncryptor
import base64
import json
from django.db import transaction

# Set up logging
logger = logging.getLogger(__name__)

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    try:
        subject = 'Your OTP Verification Code'
        message = f'Your OTP code is {otp}. It is valid for 10 minutes.'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]
        send_mail(subject, message, from_email, recipient_list)
        logger.info(f"OTP sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP to {email}: {str(e)}")
        return False

def signup(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            try:
                # Extract cleaned data after validation
                username = form.cleaned_data['username']
                email = form.cleaned_data['email']
                password = form.cleaned_data['password1']
                phone_number = form.cleaned_data['phone_number']
                cnic = form.cleaned_data['cnic']

                # Generate temporary RSA keys
                public_key, private_key = generate_keys()

                # Store signup data and keys in session
                request.session['signup_data'] = {
                    'username': username,
                    'email': email,
                    'password': password,
                    'phone_number': phone_number,
                    'cnic': cnic,
                    'public_key': json.dumps(public_key),
                    'private_key': json.dumps(private_key)
                }

                otp = generate_otp()
                request.session['otp'] = otp
                request.session['otp_email'] = email
                request.session['otp_timestamp'] = str(int(time.time()))

                if send_otp_email(email, otp):
                    messages.info(request, 'An OTP has been sent to your email.')
                    return redirect('verify_otp')
                else:
                    messages.error(request, 'Failed to send OTP. Please check your email address or try again later.')
                    # Clean up session
                    for key in ['signup_data', 'otp', 'otp_email', 'otp_timestamp']:
                        request.session.pop(key, None)
            except Exception as e:
                logger.error(f"Signup error for {form.cleaned_data['email']}: {str(e)}")
                messages.error(request, 'An error occurred during signup. Please try again.')
                for key in ['signup_data', 'otp', 'otp_email', 'otp_timestamp']:
                    request.session.pop(key, None)
        else:
            # Check for username-specific errors
            if 'username' in form.errors:
                for error in form.errors['username']:
                    if "already exists" in error.lower():
                        messages.error(request, 'User already exists. Please choose a different username.')
                    else:
                        messages.error(request, error)
            else:
                messages.error(request, 'Please correct the errors below.')
            logger.warning(f"Form validation failed: {form.errors}")
            # Clear session data to prevent proceeding with invalid data
            for key in ['signup_data', 'otp', 'otp_email', 'otp_timestamp']:
                request.session.pop(key, None)
    else:
        form = CustomUserCreationForm()
        # Clear any existing session data on GET request
        for key in ['signup_data', 'otp', 'otp_email', 'otp_timestamp']:
            request.session.pop(key, None)

    return render(request, 'chatbot/signup.html', {'form': form})


@transaction.atomic
def verify_otp(request):
    if 'otp' not in request.session or 'otp_email' not in request.session or 'signup_data' not in request.session:
        logger.warning("Unauthorized access attempt to verify_otp")
        messages.error(request, 'Unauthorized access. Please sign up first.')
        return redirect('signup')

    otp_timestamp = request.session.get('otp_timestamp')
    if otp_timestamp and (int(time.time()) - int(otp_timestamp) > 600):
        logger.warning("OTP expired")
        messages.error(request, 'OTP has expired. Please sign up again.')
        # Clean up session
        for key in ['otp', 'otp_email', 'signup_data', 'otp_timestamp']:
            request.session.pop(key, None)
        return redirect('signup')

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            entered_otp = form.cleaned_data['otp']
            if entered_otp == request.session['otp']:
                try:
                    signup_data = request.session['signup_data']
                    username = signup_data['username']
                    public_key = json.loads(signup_data['public_key'])
                    private_key = json.loads(signup_data['private_key'])

                    # Re-check username uniqueness
                    for user in User.objects.select_related('userprofile').all():
                        try:
                            profile = user.userprofile
                            user_private_key = profile.get_rsa_private_key()
                            decrypted_username = rsa_decrypt(user.username, user_private_key)
                            if decrypted_username == username:
                                logger.warning(f"Username {username} already exists during OTP verification")
                                messages.error(request, 'User already exists. Please choose a different username.')
                                # Clean up session
                                for key in ['otp', 'otp_email', 'signup_data', 'otp_timestamp']:
                                    request.session.pop(key, None)
                                return redirect('signup')
                        except UserProfile.DoesNotExist:
                            continue
                        except Exception as e:
                            logger.warning(f"Error decrypting username for user {user.id}: {str(e)}")
                            continue

                    # Create user and save to database
                    user = User(
                        username=rsa_encrypt(username, public_key, use_nonce=False),
                        email=signup_data['email'],
                        password=hash_password(signup_data['password'])
                    )
                    user.save()
                    # Create UserProfile
                    user_profile = UserProfile.objects.create(
                        user=user,
                        phone_number=rsa_encrypt(signup_data['phone_number'], public_key, use_nonce=True) if signup_data['phone_number'] else '',
                        cnic=rsa_encrypt(signup_data['cnic'], public_key, use_nonce=True) if signup_data['cnic'] else ''
                    )
                    user_profile.set_rsa_keys(public_key, private_key)
                    logger.info(f"User {username} created and saved after OTP verification")
                    login(request, user)
                    # Clean up session
                    for key in ['otp', 'otp_email', 'signup_data', 'otp_timestamp']:
                        request.session.pop(key, None)
                    messages.success(request, 'OTP verified successfully! You are now signed up.')
                    return redirect('dashboard')
                except Exception as e:
                    logger.error(f"Error during OTP verification and user creation: {str(e)}")
                    messages.error(request, 'An error occurred while verifying OTP. Please try again.')
                    # Clean up session
                    for key in ['otp', 'otp_email', 'signup_data', 'otp_timestamp']:
                        request.session.pop(key, None)
            else:
                logger.warning("Invalid OTP entered")
                messages.error(request, 'Invalid OTP. Please try again.')
        else:
            logger.warning(f"OTP form validation failed: {form.errors}")
            messages.error(request, 'Please enter a valid OTP.')
    else:
        form = OTPVerificationForm()
    return render(request, 'chatbot/verify_otp.html', {'form': form})

def verify_login_otp(request):
    if 'login_otp' not in request.session or 'login_username' not in request.session:
        logger.warning("Unauthorized access to verify_login_otp")
        messages.warning(request, 'Please login first.')
        return redirect('login')

    otp_timestamp = request.session.get('otp_timestamp')
    if otp_timestamp and (time.time() - float(otp_timestamp) > 300):
        logger.warning("OTP expired for login")
        messages.error(request, 'OTP has expired. Please login again.')
        for key in ['login_otp', 'login_username', 'otp_timestamp']:
            request.session.pop(key, None)
        return redirect('login')

    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            entered_otp = form.cleaned_data['otp']
            stored_otp = request.session['login_otp']
            if entered_otp == stored_otp:
                try:
                    username = request.session['login_username']
                    # Find user by encrypting username without nonce
                    user = None
                    for u in User.objects.select_related('userprofile').all():
                        try:
                            public_key = u.userprofile.get_rsa_public_key()
                            encrypted_username = rsa_encrypt(username, public_key, use_nonce=False)
                            if u.username == encrypted_username:
                                user = u
                                break
                        except UserProfile.DoesNotExist:
                            continue
                    if user:
                        login(request, user)
                        for key in ['login_otp', 'login_username', 'otp_timestamp']:
                            request.session.pop(key, None)
                        logger.info(f"User {username} logged in successfully")
                        messages.success(request, 'Login successful!')
                        return redirect('dashboard')
                    else:
                        logger.warning(f"User not found for username: {username}")
                        messages.error(request, 'User not found.')
                except Exception as e:
                    logger.error(f"Error during login OTP verification: {str(e)}")
                    messages.error(request, 'Login failed. Please try again.')
            else:
                logger.warning("Invalid OTP entered for login")
                messages.error(request, 'Invalid OTP.')
        else:
            logger.warning(f"OTP form validation failed: {form.errors}")
            messages.error(request, 'Please enter a valid OTP.')
    else:
        form = OTPVerificationForm()
    return render(request, 'chatbot/verify_otp.html', {
        'form': form,
        'email': request.session.get('login_username')
    })

def login_view(request):
    if request.user.is_authenticated:
        logger.info("User already authenticated, redirecting to dashboard")
        return redirect('dashboard')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not (username and password):
            logger.warning("Missing username or password")
            messages.error(request, 'Both username and password are required.')
            return render(request, 'chatbot/login.html', {'form': AuthenticationForm()})

        try:
            # Find user by encrypting username with public keys
            matched_user = None
            users = User.objects.select_related('userprofile').all()
            for user in users:
                try:
                    public_key = user.userprofile.get_rsa_public_key()
                    encrypted_username = rsa_encrypt(username, public_key, use_nonce=False)
                    if user.username == encrypted_username:
                        matched_user = user
                        break
                except UserProfile.DoesNotExist:
                    continue
                except Exception as e:
                    logger.warning(f"Error encrypting username for user {user.id}: {str(e)}")
                    continue

            if not matched_user:
                logger.warning(f"No user found with username: {username}")
                messages.error(request, 'Invalid username or password.')
                return render(request, 'chatbot/login.html', {'form': AuthenticationForm()})

            # Check for login attempt lockout
            attempt_key = f'login_attempts_{username}'
            lockout_key = f'lockout_{username}'
            attempts = request.session.get(attempt_key, 0)
            lockout_until = request.session.get(lockout_key, 0)

            current_time = time.time()
            if lockout_until > current_time:
                remaining = int(lockout_until - current_time)
                logger.warning(f"User {username} is locked out for {remaining} seconds")
                messages.error(request, f'Too many failed attempts. Account locked for {remaining} seconds.')
                return render(request, 'chatbot/login.html', {'form': AuthenticationForm()})

            if verify_password(matched_user.password, password):
                logger.info(f"Password verified for user: {username}")
                # Reset attempts on successful password
                request.session[attempt_key] = 0
                request.session.pop(lockout_key, None)
                otp = generate_otp()
                request.session['login_otp'] = otp
                request.session['login_username'] = username  # Store plaintext username
                request.session['otp_timestamp'] = str(time.time())

                if send_otp_email(matched_user.email, otp):
                    logger.info(f"OTP sent, redirecting to verify_login_otp")
                    messages.info(request, f"OTP sent to {matched_user.email}")
                    return redirect('verify_login_otp')
                else:
                    logger.error("Failed to send OTP")
                    messages.error(request, 'Failed to send OTP. Please try again later.')
                    for key in ['login_otp', 'login_username', 'otp_timestamp']:
                        request.session.pop(key, None)
            else:
                logger.warning(f"Invalid password for username: {username}")
                attempts += 1
                request.session[attempt_key] = attempts
                if attempts >= 3:
                    request.session[lockout_key] = current_time + 60  # Lock for 60 seconds
                    logger.info(f"User {username} locked out for 60 seconds")
                    messages.error(request, 'Too many failed attempts. Account locked for 60 seconds.')
                else:
                    messages.error(request, f'Invalid username or password. {3 - attempts} attempts remaining.')
        except Exception as e:
            logger.error(f"Login error for username {username}: {str(e)}")
            messages.error(request, 'An error occurred during login. Please try again.')

        return render(request, 'chatbot/login.html', {'form': AuthenticationForm()})

    logger.info("Rendering login page")
    return render(request, 'chatbot/login.html', {'form': AuthenticationForm()})

def logout_view(request):
    logger.info(f"User {request.user.username} logging out")
    logout(request)
    return redirect('/login/')

@login_required
def dashboard(request):
    documents = MedicalDocument.objects.filter(user=request.user)
    return render(request, 'chatbot/dashboard.html', {'documents': documents})

@login_required
def upload_pdf(request):
    if request.method == 'POST':
        pdf_file = request.FILES.get('pdf_file')
        if pdf_file:
          
            max_size = 5 * 1024 * 1024
            if pdf_file.size > max_size:
                messages.error(request, 'File size exceeds 5 MB limit. Please upload a smaller file.')
                return render(request, 'chatbot/upload.html')
            
            document = MedicalDocument.objects.create(user=request.user, pdf_file=pdf_file)
            pdf_path = document.pdf_file.path
            create_vector_db(pdf_path, request.user, document)
            messages.success(request, 'PDF uploaded and processed successfully!')
            return redirect('dashboard')
    return render(request, 'chatbot/upload.html')

@login_required
def chat(request):
    doc_embedding = DocumentEmbedding.objects.filter(user=request.user).last()
    if not doc_embedding:
        messages.error(request, 'Please upload a medical history PDF first.')
        return redirect('upload_pdf')

    vector_db = load_vector_db(request.user.id)
    if not vector_db:
        messages.error(request, 'No vector database found for your uploaded document.')
        return redirect('upload_pdf')

    llm = initialize_llm()
    qa_chain = setup_qa_chain(vector_db, llm)
    enc = SimpleEncryptor()

    chat_records = ChatHistory.objects.filter(user=request.user).order_by('timestamp')
    history = []
    for record in chat_records:
        try:
            query = enc.decrypt(base64.b64decode(record.query))
            response = enc.decrypt(base64.b64decode(record.response))
            history.append({'user': query, 'bot': response})
        except Exception as e:
            print(f"[Decryption Error] {e}")  # Optional logging
            continue

    if request.method == 'POST':
        query = request.POST.get('query')
        if query:
            response = qa_chain.run(query)
            queryEnc = base64.b64encode(enc.encrypt(query)).decode()
            responseEnc = base64.b64encode(enc.encrypt(response)).decode()

            ChatHistory.objects.create(user=request.user, query=queryEnc, response=responseEnc)
            return redirect('chat')
    
    return render(request, 'chatbot/chat.html', {'history': history})

def home_view(request):
    return render(request, 'chatbot/home.html')
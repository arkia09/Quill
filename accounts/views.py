from django.shortcuts import render, redirect
from .forms import UserRegistrationForm
from django.contrib.auth import login, logout
from .models import Profile
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_str, force_bytes
from .tokens import email_verification_token
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.urls import reverse


# Create your views here.
def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()

            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = email_verification_token.make_token(user)

            activation_link = request.build_absolute_uri(
                reverse("activate", kwargs={"uidb64": uid, "token": token})
            )

            send_mail(
                "Verify your email",
                f"Click the link to verify your account: {activation_link}",
                "simrankaur47937@gmail.com",
                [user.email],
            )

            return render(request, "check_email.html")

    else:
        form = UserRegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)

        if form.is_valid():
            user = form.get_user()

            if not user.profile.is_email_verified:
                messages.error(request, "Verify your email before logging in.")
                return redirect('login')

            # Log in
            login(request, user)
            return redirect('post_list')

    else:
        form = AuthenticationForm()

    return render(request, 'accounts/login.html', {'form': form})

def user_logout(request):
    logout(request)
    return redirect('post_list')

def profile_list(request):
    if request.user.is_authenticated:
        profiles = Profile.objects.exclude(user = request.user)
        return render(request, 'accounts/profile_list.html', {'profiles':profiles})
    else:
        messages.success(request, ("Please login/sign-up to view this page..."))
        return redirect('register')

def profile(request, pk):
    if request.user.is_authenticated:
        profile = Profile.objects.get(user_id=pk)
        if request.method == 'POST':
            current_user_profile =  request.user.profile
            action = request.POST['follow']
            if action == 'unfollow':
                current_user_profile.follows.remove(profile)
            else:
                current_user_profile.follows.add(profile)
            
            current_user_profile.save()
        return render(request, 'accounts/profile.html', {'profile':profile})
    else:
        messages.success(request, ("Please login/sign-up to view this page..."))
        return redirect('register')

def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user =  None

    if user and email_verification_token.check_token(user, token):
        user.profile.is_email_verified = True
        user.profile.save()
        return render(request, "activation_success.html")
    else:
        return render(request, "activation_failed.html")
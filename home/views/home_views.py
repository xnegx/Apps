import requests
from home.models import UserProfile
from home.forms import SignUpForm
from django.shortcuts import render, redirect
from django.contrib import messages

RECAPTCHA_SECRET_KEY = "6LcYkvkqAAAAAOTLusM3sdIKkqzBu-iQBiAMVMW_"

RECAPTCHA_SECRET_KEY = "6LcYkvkqAAAAAOTLusM3sdIKkqzBu-iQBiAMVMW_"  # Chave secreta

def home(request):
    if request.method == 'POST':
        email = request.POST.get('email', '')
        recaptcha_token = request.POST.get('recaptcha-token', '')

        # Verifica o reCAPTCHA v3 no servidor
        recaptcha_verify_url = "https://www.google.com/recaptcha/api/siteverify"
        data = {
            'secret': RECAPTCHA_SECRET_KEY,
            'response': recaptcha_token
        }
        response = requests.post(recaptcha_verify_url, data=data)
        result = response.json()

        if not result.get("success") or result.get("score", 0) < 0.5:
            messages.error(request, "Falha na verificação do reCAPTCHA. Tente novamente.")
            return render(request, 'home/index.html')

        if email:
            request.session['email'] = email
            return redirect('apps')
        else:
            messages.error(request, 'Por favor, insira um e-mail válido.')

    return render(request, 'home/index.html')


def apps_view(request):
    return render(request, 'home/apps.html')


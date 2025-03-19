from home.models import UserProfile
from home.forms import SignUpForm
from django.shortcuts import render, redirect
from django.contrib import messages

def home(request):
    if request.method == 'POST':
        email = request.POST['email']
        if email:
            # Armazenar o e-mail na sessão (caso necessário)
            request.session['email'] = email
            return redirect('apps')  # Redireciona para a página Apps
        else:
            messages.error(request, 'Por favor, insira um e-mail válido.')

    return render(request, 'home/index.html')


def apps_view(request):
    return render(request, 'home/apps.html')

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()  # Salva o usuário padrão
            # Salva os dados adicionais no UserProfile
            UserProfile.objects.create(
                user=user,
                nome_empresa=form.cleaned_data['nome_empresa'],
                email_corporativo=form.cleaned_data['email_corporativo'],
                solucao_criptografia=form.cleaned_data['solucao_criptografia'],
                telefone=form.cleaned_data['telefone']
            )
            messages.success(request, 'Cadastro realizado com sucesso!')
            return redirect('home')  # Redireciona para a página inicial
    else:
        form = SignUpForm()
    return render(request, 'home/signup.html', {'form': form})
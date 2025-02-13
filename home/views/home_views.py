from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from home.models import UserProfile
from home.forms import SignUpForm
def home(request):
    if request.method == 'POST':
        # Processar o formulário de login
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('apps')  # Redireciona para a página Apps após o login
        else:
            messages.error(request, 'Usuário ou senha incorretos.')

    # Exibir a página inicial com o formulário de login
    return render(request, 'home/index.html')

@login_required  # Garante que apenas usuários logados acessem esta página
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
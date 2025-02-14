from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from home.models import Certificado

# Função para verificar se o usuário é admin
def is_admin(user):
    return user.is_staff

# Decorador para garantir que somente admins possam apagar certificados
@user_passes_test(is_admin)
def apagar_certificado(request, pk):
    certificado = get_object_or_404(Certificado, pk=pk)

    if request.method == 'POST':
        certificado.delete()
        return redirect('certificados')  # Redireciona para a lista de certificados

    return redirect('certificados')  # Caso não seja POST, redireciona de volta
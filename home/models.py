from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # Relação com o usuário padrão do Django
    nome_empresa = models.CharField(max_length=100)  # Nome da empresa
    email_corporativo = models.EmailField()  # Email corporativo
    solucao_criptografia = models.CharField(max_length=100)  # Solução de criptografia utilizada
    telefone = models.CharField(max_length=20)  # Telefone

    def __str__(self):
        return self.user.username
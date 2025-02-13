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

class Certificado(models.Model):
    arquivo = models.FileField(upload_to="certificados")
    nome = models.CharField(max_length=255)
    emitido_por = models.CharField(max_length=255, blank=True, null=True)
    emitido_para = models.CharField(max_length=255, blank=True, null=True)
    validade_inicio = models.DateField(blank=True, null=True)
    validade_fim = models.DateField(blank=True, null=True)
    numero_serie = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return f"{self.nome} ({self.numero_serie})"
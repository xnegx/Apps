from django.db import models
from django.contrib.auth.models import User
import logging

logger = logging.getLogger(__name__)  # Configura o logger

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # Relação com o usuário padrão do Django
    nome_empresa = models.CharField(max_length=100)  # Nome da empresa
    email_corporativo = models.EmailField()  # Email corporativo
    solucao_criptografia = models.CharField(max_length=100)  # Solução de criptografia utilizada
    telefone = models.CharField(max_length=20)  # Telefone

    def __str__(self):
        return self.user.username

class Certificado(models.Model):
    arquivo = models.FileField(upload_to='certificados/')
    nome = models.CharField(max_length=255)
    emitido_por = models.CharField(max_length=255)
    emitido_para = models.CharField(max_length=255)
    validade_inicio = models.DateField()
    validade_fim = models.DateField()
    numero_serie = models.CharField(max_length=255)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['numero_serie', 'emitido_por'], name='unique_certificado_emitido_por')
        ]

    def save(self, *args, **kwargs):
        """ Impede a duplicação sem gerar erro """
        if not Certificado.objects.filter(numero_serie=self.numero_serie, emitido_por=self.emitido_por).exists():
            super().save(*args, **kwargs)  # Salva normalmente se não existir
        else:
            logger.info(f"O certificado {self.numero_serie} - {self.emitido_por} já existe na base.")  # Usa logging sem ❌

    def __str__(self):
        return f"{self.nome} - {self.numero_serie} - {self.emitido_por}"
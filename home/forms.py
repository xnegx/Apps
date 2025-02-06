from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile

class SignUpForm(UserCreationForm):
    nome_empresa = forms.CharField(max_length=100, required=True)
    email_corporativo = forms.EmailField(required=True)
    solucao_criptografia = forms.CharField(max_length=100, required=True)
    telefone = forms.CharField(max_length=20, required=True)

    class Meta:
        model = User
        fields = ('username', 'password1', 'password2', 'nome_empresa', 'email_corporativo', 'solucao_criptografia', 'telefone')

class CSRTextForm(forms.Form):
    csr_text = forms.CharField(
        label="Cole o conteúdo da CSR aqui",
        widget=forms.Textarea(attrs={'rows': 10, 'cols': 50}),
    )
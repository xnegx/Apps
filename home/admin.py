from django.contrib import admin
from .models import UserProfile

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'nome_empresa', 'email_corporativo', 'solucao_criptografia', 'telefone')
    search_fields = ('user__username', 'email_corporativo', 'nome_empresa')

admin.site.register(UserProfile, UserProfileAdmin)
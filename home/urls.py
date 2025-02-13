from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name='home'),  # Rota para a página inicial
    path('apps/', views.apps_view, name='apps'),  # Página Apps (após login)
    path('logout/', auth_views.LogoutView.as_view(next_page='home'), name='logout'),  # Redireciona para a página inicial após o logout
    path('signup/', views.signup_view, name='signup'),  # Rota para o cadastro
    path('csr_decoder/', views.csr_decoder, name='csr_decoder'), # Rota para o csr decoder
    path('header/', views.header, name='header'),# Rota para o header
    path("certificados/", views.certificate_views.listar_certificados, name="certificados"), # Rota para lista de certificados
    path("certificados/<int:cert_id>/", views.certificate_views.detalhes_certificado, name="detalhes_certificado"), # Rota para detalhe do certificado
    path('certificados/<int:pk>/download/', views.download_certificado, name='download_certificado'), # Rota para download do certificado
]
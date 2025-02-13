from django.shortcuts import render
from home.models import Certificado

def listar_certificados(request):
    certificados = Certificado.objects.all()
    return render(request, "home/certificados/certificados.html", {"certificados": certificados})

def detalhes_certificado(request, cert_id):
    certificado = Certificado.objects.get(id=cert_id)
    return render(request, "home/certificados/detalhes_certificado.html", {"certificado": certificado})
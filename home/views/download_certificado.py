from django.shortcuts import get_object_or_404
from django.http import FileResponse, HttpResponse
from home.models import Certificado

def download_certificado(request, pk):
    certificado = get_object_or_404(Certificado, pk=pk)

    if certificado.arquivo and hasattr(certificado.arquivo, 'path'):
        response = FileResponse(certificado.arquivo.open('rb'), as_attachment=True, filename=certificado.arquivo.name)
        return response
    else:
        return HttpResponse("Arquivo não encontrado", status=404)

import mimetypes
import os
from django.shortcuts import get_object_or_404
from django.http import FileResponse, HttpResponse
from home.models import Certificado

def download_certificado(request, certificado_id):
    """ View para baixar um certificado do banco de dados pelo ID """
    certificado = get_object_or_404(Certificado, id=certificado_id)

    if not certificado.arquivo:
        return HttpResponse("Arquivo não encontrado", status=404)

    file_path = certificado.arquivo.path
    file_name = os.path.basename(file_path)

    # Garante que o navegador baixe com o nome correto
    response = HttpResponse(content_type='application/x-x509-ca-cert')
    response['Content-Disposition'] = f'attachment; filename="{file_name}"'

    # Lendo e retornando o conteúdo do arquivo
    with open(file_path, 'rb') as f:
        response.write(f.read())

    return response
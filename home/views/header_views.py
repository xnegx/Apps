from datetime import datetime

from django.http import FileResponse
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from OpenSSL import crypto
from home.models import Certificado
import struct

# Mapeamento de campos conforme a tabela SFN
HEADER_FIELDS = [
    ("Tamanho total do Cabeçalho", "H", 2),
    ("Versão do Protocolo de Segurança", "B", 1),
    ("Código de erro", "B", 1),
    ("Indicação de tratamento especial", "B", 1),
    ("Reservado para uso futuro", "B", 1),
    ("Algoritmo da chave assimétrica do destino", "B", 1),
    ("Algoritmo da chave simétrica", "B", 1),
    ("Algoritmo da chave assimétrica local", "B", 1),
    ("Algoritmo de hash", "B", 1),
    ("PC do certificado digital do destino", "B", 1),
    ("Série do certificado digital do destino", "32s", 32),
    ("PC do certificado digital da Instituição", "B", 1),
    ("Série do certificado digital da Instituição", "32s", 32),
]

# Mapeamento de valores possíveis para alguns campos
TRANSLATIONS = {
    "Versão do Protocolo de Segurança": {0x00: "Em claro", 0x02: "Segunda versão", 0x03: "Terceira versão"},
    "Algoritmo da chave assimétrica do destino": {0x01: "RSA 1024 bits", 0x02: "RSA 2048 bits"},
    "Algoritmo da chave simétrica": {0x01: "Triple-DES", 0x02: "AES-256"},
    "Algoritmo de hash": {0x02: "SHA-1", 0x03: "SHA-256"},
    "PC do certificado digital do destino": {0x01: "SPB-Serpro", 0x02: "SPB-Certisign", 0x03: "Pessoas Físicas"},
    "PC do certificado digital da Instituição": {0x01: "SPB-Serpro", 0x02: "SPB-Certisign", 0x03: "Pessoas Físicas"},
    "Código de erro": {
        0x00: "00H - Sem erros, segurança conferida",
        0x01: "01H - EGEN9901 - Tamanho do cabeçalho inválido",
        0x02: "02H - EGEN9902 - Versão inválida ou incompatível",
        0x03: "03H - EGEN9903 - Algoritmo da chave do destinatário inválido",
        0x04: "04H - EGEN9904 - Algoritmo simétrico inválido",
        0x05: "05H - EGEN9905 - Algoritmo da chave do certificado digital inválido",
        0x06: "06H - EGEN9906 - Algoritmo de hash inválido",
        0x07: "07H - EGEN9907 - Código da PC do certificado do destinatário inválido",
        0x08: "08H - EGEN9908 - Número de série do certificado do destinatário inválido",
        0x09: "09H - EGEN9909 - Código da PC do certificado inválido",
        0x0A: "0AH - EGEN9910 - Número de série do certificado digital da Instituição inválido",
        0x0B: "0BH - EGEN9911 - Criptograma de autenticação da Mensagem inválido",
        0x0C: "0CH - EGEN9912 - Certificado não é do emissor da mensagem",
        0x0D: "0DH - EGEN9913 - Erro na extração da chave simétrica",
        0x0E: "0EH - EGEN9914 - Erro gerado pelo algoritmo simétrico",
        0x0F: "0FH - EGEN9915 - Tamanho da mensagem não múltiplo de 8 bytes",
        0x10: "10H - EGEN9916 - Certificado usado não está ativado",
        0x11: "11H - EGEN9917 - Certificado usado está vencido ou revogado",
        0x12: "12H - EGEN9918 - Erro genérico de software",
        0x13: "13H - EGEN9919 - Indicação de uso específico inválida",
        0x14: "14H - EGEN9920 - Certificado inválido",
    }
}

def parse_binary_header(binary_data):
    """
    Lê o arquivo binário e extrai os campos definidos na tabela.
    """
    offset = 0
    parsed_data = {}

    for field_name, fmt, size in HEADER_FIELDS:
        value = struct.unpack_from(">" + fmt, binary_data, offset)[0]
        offset += size

        if field_name in ["Série do certificado digital do destino", "Série do certificado digital da Instituição"]:
            if isinstance(value, bytes):
                value_str = value.decode('utf-8')
            else:
                value_str = str(value)
            value_clean = value_str.lstrip('0')
            value_clean = value_clean if value_clean else "0"
            value = value_clean

        translated_value = TRANSLATIONS.get(field_name, {}).get(value, value)
        parsed_data[field_name] = translated_value

    return parsed_data

def load_certificate(cert_file):
    """
    Carrega um certificado em formato PEM ou DER e o converte para OpenSSL.crypto.X509.
    """
    cert_data = cert_file.read()

    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    else:
        return crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)

def compare_certificates(binary_serial, cert_serial):
    """
    Compara os números de série extraídos do binário e do certificado.
    """
    if isinstance(binary_serial, bytes):
        binary_serial_hex = binary_serial.hex().lstrip('0').upper()
    elif isinstance(binary_serial, str):
        try:
            binary_serial_int = int(binary_serial)
            binary_serial_hex = hex(binary_serial_int)[2:].lstrip('0').upper()
        except ValueError:
            binary_serial_hex = binary_serial.lstrip('0').upper()
    else:
        raise TypeError("Tipo de dado 'binary_serial' não suportado.")

    if isinstance(cert_serial, int):
        cert_serial_hex = hex(cert_serial)[2:].lstrip('0').upper()
    elif isinstance(cert_serial, str):
        try:
            cert_serial_int = int(cert_serial)
            cert_serial_hex = hex(cert_serial_int)[2:].lstrip('0').upper()
        except ValueError:
            cert_serial_hex = cert_serial.lstrip('0').upper()
    else:
        raise TypeError("Tipo de dado 'cert_serial' não suportado.")

    return binary_serial_hex == cert_serial_hex

def get_distinguished_name(cert):
    """
    Converte o Distinguished Name em uma string legível.
    """
    subject = cert.get_subject()
    dn_parts = []

    for attribute in subject.get_components():
        # Converte os componentes do Distinguished Name para um formato legível
        dn_parts.append(f"{attribute[0].decode('utf-8')}={attribute[1].decode('utf-8')}")

    return ','.join(dn_parts)


def convert_cert_date(cert_date):
    try:
        return datetime.strptime(cert_date.decode("utf-8"), "%Y%m%d%H%M%SZ").date()
    except ValueError as e:
        raise ValueError(f"Erro ao converter data: {e}")

def buscar_certificado(serial):
    try:
        # Agora a busca é feita apenas pelo número de série
        certificado = Certificado.objects.get(numero_serie=serial)
        print(f"Certificado encontrado: {certificado}")  # Log de depuração
        return certificado
    except Certificado.DoesNotExist:
        print(f"Certificado não encontrado para a série: {serial}")
        return None

def get_issuer_common_name(cert):
    """ Obtém o nome comum do emissor de um certificado """
    return dict(cert.get_issuer().get_components()).get(b'CN', b'').decode('utf-8')

def get_serial_number_hex(cert_serial):
    """ Converte o número de série do certificado para formato hexadecimal """
    return hex(int(cert_serial))[2:].lstrip('0').upper()


def header(request):
    parsed_data = None
    cert_verification = None
    error = None
    certificados_encontrados = {}

    if request.method == "POST" and request.FILES:
        try:
            binary_file = request.FILES.get("binary_file")
            cert_origin = request.FILES.get("cert_origin")
            cert_destination = request.FILES.get("cert_destination")

            if not binary_file:
                raise ValueError("Por favor, envie um arquivo binário.")

            binary_data = binary_file.read()
            parsed_data = parse_binary_header(binary_data)

            binary_cert_origin_serial = parsed_data["Série do certificado digital da Instituição"]
            binary_cert_destination_serial = parsed_data["Série do certificado digital do destino"]

            # Verificando se o certificado de origem foi enviado
            if cert_origin:
                certificados_encontrados["origem"] = buscar_certificado(binary_cert_origin_serial)

            # Verificando se o certificado de destino foi enviado
            if cert_destination:
                certificados_encontrados["destino"] = buscar_certificado(binary_cert_destination_serial)

            # Caso apenas o arquivo binário tenha sido enviado
            if not cert_origin and not cert_destination:
                # Buscar certificados de origem e destino com base no arquivo binário
                certificados_encontrados["origem"] = buscar_certificado(binary_cert_origin_serial)
                certificados_encontrados["destino"] = buscar_certificado(binary_cert_destination_serial)

            # Se ambos os certificados foram enviados, realizar a comparação
            if cert_origin and cert_destination:
                cert_origin_data = load_certificate(cert_origin)
                cert_destination_data = load_certificate(cert_destination)

                cert_origin_serial = get_serial_number_hex(cert_origin_data.get_serial_number())
                cert_destination_serial = get_serial_number_hex(cert_destination_data.get_serial_number())
                cert_origin_emissor = get_issuer_common_name(cert_origin_data)
                cert_destination_emissor = get_issuer_common_name(cert_destination_data)

                cert_verification = {
                    "certificado_origem": compare_certificates(binary_cert_origin_serial, cert_origin_serial),
                    "certificado_destino": compare_certificates(binary_cert_destination_serial,
                                                                cert_destination_serial),
                    "emissor_origem": cert_origin_emissor,
                    "emissor_destino": cert_destination_emissor,
                    "serie_origem": cert_origin_serial,
                    "serie_destino": cert_destination_serial,
                }

            elif cert_origin:  # Caso somente o certificado de origem tenha sido enviado
                cert_origin_data = load_certificate(cert_origin)
                cert_origin_serial = get_serial_number_hex(cert_origin_data.get_serial_number())
                cert_origin_emissor = get_issuer_common_name(cert_origin_data)

                cert_verification = {
                    "certificado_origem": True,
                    "emissor_origem": cert_origin_emissor,
                    "serie_origem": cert_origin_serial,
                }

                # Buscar o certificado de destino com base no número de série do binário
                certificados_encontrados["destino"] = buscar_certificado(binary_cert_destination_serial)

            elif cert_destination:  # Caso somente o certificado de destino tenha sido enviado
                cert_destination_data = load_certificate(cert_destination)
                cert_destination_serial = get_serial_number_hex(cert_destination_data.get_serial_number())
                cert_destination_emissor = get_issuer_common_name(cert_destination_data)

                cert_verification = {
                    "certificado_destino": True,
                    "emissor_destino": cert_destination_emissor,
                    "serie_destino": cert_destination_serial,
                }

                # Buscar o certificado de origem com base no número de série do binário
                certificados_encontrados["origem"] = buscar_certificado(binary_cert_origin_serial)

            # Salvar os certificados no banco de dados, caso sejam enviados
            if cert_origin:
                Certificado.objects.create(
                    arquivo=cert_origin,
                    nome=cert_origin_data.get_subject().CN,  # Nome (CN) do Certificado
                    emitido_por=cert_origin_data.get_issuer().commonName,
                    emitido_para=get_distinguished_name(cert_origin_data),  # Emitido Para (Distinguished Name completo)
                    validade_inicio=convert_cert_date(cert_origin_data.get_notBefore()),  # Validade Início
                    validade_fim=convert_cert_date(cert_origin_data.get_notAfter()),  # Validade Fim
                    numero_serie=cert_origin_serial
                )

            if cert_destination:
                Certificado.objects.create(
                    arquivo=cert_destination,
                    nome=cert_destination_data.get_subject().CN,  # Nome (CN) do Certificado
                    emitido_por=cert_destination_data.get_issuer().commonName,
                    emitido_para=get_distinguished_name(cert_destination_data),
                    validade_inicio=convert_cert_date(cert_destination_data.get_notBefore()),  # Validade Início
                    validade_fim=convert_cert_date(cert_destination_data.get_notAfter()),  # Validade Fim
                    numero_serie=cert_destination_serial
                )

        except Exception as e:
            error = f"Erro ao processar os arquivos: {str(e)}"

    return render(
        request,
        "home/header.html",
        {"parsed_data": parsed_data, "cert_verification": cert_verification,
         "certificados_encontrados": certificados_encontrados, "error": error}
    )

@login_required
def download_certificado(request, certificado_id):
    """
    Permite o download de um certificado encontrado no banco de dados.
    """
    certificado = Certificado.objects.get(id=certificado_id)
    return FileResponse(certificado.arquivo, as_attachment=True, filename=certificado.nome + ".crt")
from OpenSSL import crypto
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .forms import SignUpForm  # Importe o SignUpForm
from .models import UserProfile  # Importe o UserProfile
from OpenSSL import crypto
from cryptography import x509
import struct

def home(request):
    if request.method == 'POST':
        # Processar o formulário de login
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('apps')  # Redireciona para a página Apps após o login
        else:
            messages.error(request, 'Usuário ou senha incorretos.')

    # Exibir a página inicial com o formulário de login
    return render(request, 'home/index.html')

@login_required  # Garante que apenas usuários logados acessem esta página
def apps_view(request):
    return render(request, 'home/apps.html')

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()  # Salva o usuário padrão
            # Salva os dados adicionais no UserProfile
            UserProfile.objects.create(
                user=user,
                nome_empresa=form.cleaned_data['nome_empresa'],
                email_corporativo=form.cleaned_data['email_corporativo'],
                solucao_criptografia=form.cleaned_data['solucao_criptografia'],
                telefone=form.cleaned_data['telefone']
            )
            messages.success(request, 'Cadastro realizado com sucesso!')
            return redirect('home')  # Redireciona para a página inicial
    else:
        form = SignUpForm()
    return render(request, 'home/signup.html', {'form': form})

@login_required
def csr_decoder(request):
    csr_data = None
    error = None

    if request.method == "POST":
        csr_text = request.POST.get("csr_text", "").strip()

        if csr_text:
            try:
                # Carregar a CSR a partir do texto inserido pelo usuário
                csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_text.encode())

                subject = csr.get_subject()
                pub_key = csr.get_pubkey()
                pub_key_bits = pub_key.bits()

                # Tentar obter o algoritmo de assinatura
                try:
                    signature_algorithm = csr.get_signature_algorithm().decode()
                except AttributeError:
                    # Se `get_signature_algorithm()` não estiver disponível, extraímos manualmente
                    csr_cryptography = x509.load_pem_x509_csr(csr_text.encode())
                    signature_algorithm = csr_cryptography.signature_algorithm_oid._name

                # Criar dicionário com as informações extraídas
                csr_data = {
                    "Common Name (CN)": getattr(subject, "CN", "N/A"),
                    "Organization (O)": getattr(subject, "O", "N/A"),
                    "Organizational Unit (OU)": getattr(subject, "OU", "N/A"),
                    "Country (C)": getattr(subject, "C", "N/A"),
                    "State/Province (ST)": getattr(subject, "ST", "N/A"),
                    "Locality (L)": getattr(subject, "L", "N/A"),
                    "Email Address": getattr(subject, "emailAddress", "N/A"),
                    "Public Key Bits": pub_key_bits,
                    "Signature Algorithm": signature_algorithm,
                }
            except Exception as e:
                error = f"Erro ao processar a CSR: {str(e)}"
        else:
            error = "Por favor, insira uma CSR válida."

    return render(request, "home/csr_decoder.html", {"csr_data": csr_data, "error": error})

# Mapeamento de campos conforme a tabela SFN
HEADER_FIELDS = [
    ("Tamanho total do Cabeçalho", "H", 2),  # 2 bytes (024CH = 588 decimal)
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

    # Mapeamento atualizado para o Código de Erro
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

        # Tratamento especial para os campos de série (se houver)
        if field_name in ["Série do certificado digital do destino", "Série do certificado digital da Instituição"]:
            if isinstance(value, bytes):
                value_str = value.decode('utf-8')  # Converte bytes para string
            else:
                value_str = str(value)  # Garante que seja uma string
            # Remove os zeros à esquerda
            value_clean = value_str.lstrip('0')
            # Se todos os caracteres forem zeros, define como "0"
            value_clean = value_clean if value_clean else "0"
            value = value_clean


        # Traduzir o valor se houver uma tradução definida
        translated_value = TRANSLATIONS.get(field_name, {}).get(value, value)
        parsed_data[field_name] = translated_value

    return parsed_data

def load_certificate(cert_file):
    """
    Carrega um certificado em formato PEM ou DER e o converte para OpenSSL.crypto.X509.
    """
    cert_data = cert_file.read()

    # Verificar se o certificado está no formato PEM
    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    else:
        return crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)
def compare_certificates(binary_serial, cert_serial):
    """
    Compara o número de série extraído do binário com o número de série do certificado,
    convertendo ambos para hexadecimal para comparação consistente.
    """

    # Converter número de série binário para hexadecimal
    if isinstance(binary_serial, bytes):
        binary_serial_hex = binary_serial.hex().lstrip('0').upper()  # Converte bytes para hex, remove zeros à esquerda e torna maiúsculas
    elif isinstance(binary_serial, str):
        try:
            # Tentar converter string para int (se for um decimal) e depois para hex
            binary_serial_int = int(binary_serial)
            binary_serial_hex = hex(binary_serial_int)[2:].lstrip('0').upper()
        except ValueError:
            # Se não for um decimal, assumir que já está em hexadecimal (e limpar)
            binary_serial_hex = binary_serial.lstrip('0').upper()
    else:
        raise TypeError("Tipo de dado 'binary_serial' não suportado.")

    # Converter número de série do certificado para hexadecimal
    if isinstance(cert_serial, int):
        cert_serial_hex = hex(cert_serial)[2:].lstrip('0').upper()  # Converte int para hex, remove "0x" e torna maiúsculas
    elif isinstance(cert_serial, str):
        try:
            # Tentar converter string para int (se for um decimal) e depois para hex
            cert_serial_int = int(cert_serial)
            cert_serial_hex = hex(cert_serial_int)[2:].lstrip('0').upper()
        except ValueError:
            # Se não for um decimal, assumir que já está em hexadecimal (e limpar)
            cert_serial_hex = cert_serial.lstrip('0').upper()
    else:
        raise TypeError("Tipo de dado 'cert_serial' não suportado.")


    print(f"Binary Serial (Hex): {binary_serial_hex}")
    print(f"Certificate Serial (Hex): {cert_serial_hex}")

    return binary_serial_hex == cert_serial_hex

@login_required
def header(request):
    parsed_data = None
    cert_verification = None
    error = None

    if request.method == "POST" and request.FILES:
        try:
            binary_file = request.FILES.get("binary_file")
            cert_origin = request.FILES.get("cert_origin")
            cert_destination = request.FILES.get("cert_destination")

            if not binary_file:
                raise ValueError("Por favor, envie um arquivo binário.")

            # Ler e processar o arquivo binário
            binary_data = binary_file.read()
            parsed_data = parse_binary_header(binary_data)

            # Comparação com certificados (se enviados)
            if cert_origin and cert_destination:
                cert_origin_data = load_certificate(cert_origin)
                cert_destination_data = load_certificate(cert_destination)

                cert_origin_serial = str(cert_origin_data.get_serial_number())
                cert_destination_serial = str(cert_destination_data.get_serial_number())

                binary_cert_origin_serial = parsed_data["Série do certificado digital da Instituição"]
                binary_cert_destination_serial = parsed_data["Série do certificado digital do destino"]

                cert_verification = {
                    "certificado_origem": compare_certificates(binary_cert_origin_serial, cert_origin_serial),
                    "certificado_destino": compare_certificates(binary_cert_destination_serial,
                                                                cert_destination_serial),
                    "emissor_origem": cert_origin_data.get_issuer().commonName,
                    "emissor_destino": cert_destination_data.get_issuer().commonName,
                    "serie_origem": hex(int(cert_origin_serial))[2:].lstrip('0').upper(),  # Convertendo para hex
                    "serie_destino": hex(int(cert_destination_serial))[2:].lstrip('0').upper(),  # Convertendo para hex
                }

        except Exception as e:
            error = f"Erro ao processar os arquivos: {str(e)}"

    return render(request, "home/header.html", {"parsed_data": parsed_data, "cert_verification": cert_verification, "error": error})

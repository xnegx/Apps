from OpenSSL import crypto
from cryptography import x509
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

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
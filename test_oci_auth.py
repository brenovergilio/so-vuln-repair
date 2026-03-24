import oci
import os
from dotenv import load_dotenv

load_dotenv()

print("🔍 Testando autenticação com a Oracle Cloud...")

try:
    # 1. Tenta carregar o arquivo
    profile = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")
    config = oci.config.from_file(profile_name=profile)
    print("✅ Arquivo ~/.oci/config lido com sucesso!")
    
    # 2. Valida se os campos obrigatórios estão preenchidos corretamente
    oci.config.validate_config(config)
    print("✅ Estrutura do config e caminho da chave validados!")
    
    # 3. Tenta bater na API de Identidade para provar que a chave funciona
    identity = oci.identity.IdentityClient(config)
    response = identity.get_user(config["user"])
    
    if response and getattr(response, 'data', None):
        print(f"🎉 SUCESSO! Autenticado na OCI como: {response.data}")
    else:
        print("⚠️ A autenticação passou, mas a API não retornou os dados do usuário.")

except oci.exceptions.ConfigFileNotFound:
    print("❌ ERRO: O arquivo ~/.oci/config não foi encontrado.")
except oci.exceptions.InvalidConfig:
    print("❌ ERRO: O arquivo config está mal formatado ou a chave não foi encontrada.")
except oci.exceptions.ServiceError as e:
    print(f"❌ ERRO DE SERVIÇO OCI: {e.message}")
except Exception as e:
    print(f"❌ ERRO DESCONHECIDO: {e}")
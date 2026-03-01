import os
import oci
import time
import requests
from dotenv import load_dotenv

load_dotenv()

class LLMClient:
    def __init__(self, provider="oci"):
        """
        provider: 'oci' para Oracle Cloud (70B) ou 'local' para rede local (8B)
        """
        self.provider = provider.lower()

        if self.provider == "oci":
            self._init_oci()
        elif self.provider == "local":
            self._init_local()
        else:
            raise ValueError(f"❌ ERROR: Unknown provider '{provider}'. Use 'oci' or 'local'.")

    def _init_oci(self):
        self.compartment_id = os.getenv("OCI_COMPARTMENT_ID")
        self.model_id = os.getenv("OCI_MODEL_ID")
        self.endpoint = os.getenv("OCI_SERVICE_ENDPOINT")
        profile = os.getenv("OCI_CONFIG_PROFILE", "DEFAULT")

        if not all([self.compartment_id, self.model_id, self.endpoint]):
            raise ValueError("❌ ERROR: OCI environment variables missing in .env")

        try:
            config = oci.config.from_file(profile_name=profile)
            self.client = oci.generative_ai_inference.GenerativeAiInferenceClient(
                config=config,
                service_endpoint=self.endpoint,
                retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY
            )
            print("✅ Conectado à Oracle Cloud Infrastructure (OCI).")
        except Exception as e:
            print(f"❌ OCI Authentication Error: {e}")
            raise e

    def _init_local(self):
        # Configurações para a sua máquina na rede local
        self.local_url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/v1/chat/completions")
        self.local_model = os.getenv("LOCAL_LLM_MODEL", "llama3.1")
        print(f"✅ Configurado para LLM Local -> {self.local_url} (Model: {self.local_model})")

    def generate_completion(self, system_prompt, user_prompt, temperature=None):        
        if temperature is None:
            temp_env = os.getenv("TEMPERATURE", "0.0")
            temperature = float(temp_env) if temp_env else 0.0

        if self.provider == "oci":
            return self._generate_oci(system_prompt, user_prompt, temperature)
        elif self.provider == "local":
            return self._generate_local(system_prompt, user_prompt, temperature)

    def _generate_oci(self, system_prompt, user_prompt, temperature):
        # Simula o texto completo apenas para a nossa matemática de custo e tokens
        simulated_full_text = system_prompt + "\n\n" + user_prompt
        
        # 1. Monta a requisição usando o formato de Chat Universal (GenericChatRequest)
        chat_request = oci.generative_ai_inference.models.GenericChatRequest(
            api_format="GENERIC",
            messages=[
                oci.generative_ai_inference.models.Message(
                    role="SYSTEM",
                    content=[oci.generative_ai_inference.models.TextContent(type="TEXT", text=system_prompt)]
                ),
                oci.generative_ai_inference.models.Message(
                    role="USER",
                    content=[oci.generative_ai_inference.models.TextContent(type="TEXT", text=user_prompt)]
                )
            ],
            max_tokens=2048,
            temperature=temperature,
            top_p=1.0,
            is_stream=False
        )

        # 2. Empacota os detalhes para a API de Chat
        details = oci.generative_ai_inference.models.ChatDetails(
            compartment_id=self.compartment_id,
            serving_mode=oci.generative_ai_inference.models.OnDemandServingMode(model_id=self.model_id),
            chat_request=chat_request
        )

        try:
            # 3. Dispara a requisição usando o método client.chat() em vez de generate_text()
            response = self.client.chat(details)
            if response is None: return None
            
            # 4. A extração da resposta muda para navegar no objeto de Chat
            generated_text = response.data.chat_response.choices[0].message.content[0].text.strip()
            
            return {
                "text": generated_text,
                "input_chars": len(simulated_full_text),
                "output_chars": len(generated_text)
            }

        except oci.exceptions.ServiceError as e:
            if e.status == 429:
                print("⏳ OCI Rate Limit hit. Waiting 10s...")
                time.sleep(10)
                return self._generate_oci(system_prompt, user_prompt, temperature)
            else:
                print(f"❌ OCI Service Error: {e.message}")
                return None

    def _generate_local(self, system_prompt, user_prompt, temperature):
        # Formatação usando o padrão Universal OpenAI (compatível com Ollama/vLLM)
        payload = {
            "model": self.local_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature,
            "max_tokens": 2048
        }
        
        # Concatenação simulada apenas para manter a métrica de caracteres no retorno
        simulated_full_text = system_prompt + user_prompt 
        
        try:
            response = requests.post(self.local_url, json=payload, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            generated_text = result["choices"][0]["message"]["content"].strip()
            
            return {
                "text": generated_text,
                "input_chars": len(simulated_full_text),
                "output_chars": len(generated_text)
            }
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Local LLM API Error: {e}")
            return None
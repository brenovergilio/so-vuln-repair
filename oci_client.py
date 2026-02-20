import os
import oci
import time
from dotenv import load_dotenv

load_dotenv()

class OCIClient:
    def __init__(self):
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
        except Exception as e:
            print(f"❌ OCI Authentication Error: {e}")
            raise e

    def generate_completion(self, system_prompt, user_prompt, temperature=None):        
        if temperature is None:
            # Lida com segurança caso a variável no .env esteja vazia ou ausente
            temp_env = os.getenv("TEMPERATURE", "0.0")
            temperature = float(temp_env) if temp_env else 0.0

        # Formatação exata do prompt para a arquitetura Llama 3
        full_text = f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n{system_prompt}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n{user_prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"

        llm_request = oci.generative_ai_inference.models.LlamaLlmInferenceRequest(
            prompt=full_text,
            max_tokens=2048,
            temperature=temperature,
            top_p=1.0,
            is_stream=False
        )

        details = oci.generative_ai_inference.models.GenerateTextDetails(
            compartment_id=self.compartment_id,
            serving_mode=oci.generative_ai_inference.models.OnDemandServingMode(model_id=self.model_id),
            inference_request=llm_request
        )

        try:
            response = self.client.generate_text(details)
            
            if response is None:
              return None
            
            # Extrai o texto gerado pela LLM
            generated_text = response.data.inference_response.choices[0].text.strip()
            
            # Calcula os caracteres exatos para métrica de custo precisa na OCI
            # e estima os tokens para o registro no CSV.
            input_chars = len(full_text)
            output_chars = len(generated_text)
            
            return {
                "text": generated_text,
                "input_chars": input_chars,
                "output_chars": output_chars
            }

        except oci.exceptions.ServiceError as e:
            if e.status == 429:
                print("⏳ OCI Rate Limit hit. Waiting 10s...")
                time.sleep(10)
                return self.generate_completion(system_prompt, user_prompt, temperature)
            else:
                print(f"❌ OCI Service Error: {e.message}")
                return None
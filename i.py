from huggingface_hub import InferenceClient
# Use a pipeline as a high-level helper
from transformers import pipeline


api_token = "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"
pipe = pipeline("text-generation", model="inessiness/gpt2-fr-articles")

# Load model directly
from transformers import AutoTokenizer, AutoModelForCausalLM

tokenizer = AutoTokenizer.from_pretrained("inessiness/gpt2-fr-articles")
model = AutoModelForCausalLM.from_pretrained("inessiness/gpt2-fr-articles")
import requests

def generate_html_from_description(description):
    endpoint = "https://api.openai.com/v1/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer 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"
    }
    data = {
        "model": "text-davinci-003",
        "prompt": f"Generate HTML based on the description: {description}",
        "max_tokens": 4000,
        "temperature": 1
    }
    
    response = requests.post(endpoint, headers=headers, json=data)
    response.raise_for_status()
    html_text = response.json()["choices"][0]["text"]
    return html_text

# Esempio di utilizzo
description = "interfaccia di sito di e-commerce con lo stile di un sito di design e molti elementi rossi"
generated_html = generate_html_from_description(description)

# Stampiamo l'HTML generato
print(generated_html)

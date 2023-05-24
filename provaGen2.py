import requests

def generate_html_from_description(description):
    # Lettura del contenuto del file output.html
    with open("output.html", "r") as file:
        html_content = file.read()

    # Composizione del prompt con la descrizione dell'utente e il contenuto del file HTML
    prompt = f"Alterare il codice HTML che ti invio nel modo seguente: {description}\n\n{html_content}"

    # Chiamata all'API di completamento di OpenAI
    endpoint = "https://api.openai.com/v1/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer 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"
    }
    data = {
        "model": "text-davinci-003",
        "prompt": prompt,
        "max_tokens": 3500,
        "temperature": 1
    }
    
    response = requests.post(endpoint, headers=headers, json=data)
    response.raise_for_status()
    html_text = response.json()["choices"][0]["text"]
    return html_text

# Esempio di utilizzo
description = "modifica lo stile del sito, rendendo più accattivanti i componenti o aggiungendone, per farlo risultare simile ad un sito di design con colori gialli e blu"
generated_html = generate_html_from_description(description)

# Stampiamo l'HTML generato
print(generated_html)

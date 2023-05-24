import openai
import webbrowser

def generate_html_from_description(description):
    # Lettura del contenuto del file output.html
    with open("output.html", "r") as file:
        html_content = file.read()

    # Composizione del prompt con la descrizione dell'utente e il contenuto del file HTML
    prompt = f"Alterare il codice HTML che ti invio nel modo seguente: {description}\n\n{html_content}"

    # Impostazione della chiave API
    openai.api_key = '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'

    # Chiamata all'API di completamento di OpenAI
    response = openai.Completion.create(
        engine='text-davinci-003',
        prompt=prompt,
        max_tokens=3500,
        temperature=1
    )

    html_text = response.choices[0].text
    api_usage = response['usage']
    print('Total token consumed: {0}'.format(api_usage['total_tokens']))

    # Salva l'HTML generato su file
    with open("basic.html", "w") as file:
        file.write(html_text)

    # Apri il file HTML con Microsoft Edge
    webbrowser.open("basic.html")

# Esempio di utilizzo
description = "aggiungi un bottone nero con scritta ciao che faccia comparire, se cliccato, una scritta blu"
generate_html_from_description(description)

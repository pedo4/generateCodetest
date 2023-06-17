import subprocess

# Imposta i nomi delle risorse
nome_acr = 'srs2023.azurecr.io'
nome_immagine_locale = 'e_comm2'
nome_immagine_acr = 'samples/e_comm3'

def login_azure():
    subprocess.run('az login', shell=True)

def push_docker_image():
    subprocess.run(
        f'docker tag {nome_immagine_locale} {nome_acr}/{nome_immagine_acr}',
        shell=True
    )
    subprocess.run(
        f'docker push {nome_acr}/{nome_immagine_acr}',
        shell=True
    )

# Esegui il processo di automazione
login_azure()
push_docker_image()


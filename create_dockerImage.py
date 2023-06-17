import subprocess

# Imposta i nomi delle risorse
nome_immagine_locale = 'e_comm_3'
cartella_dockerfile = 'C:/Users/Alessandro/Documents/Unibo/SRS/e-comm'  # Inserisci il percorso completo alla cartella contenente il Dockerfile

def build_docker_image():
    subprocess.run(
        f'docker build -t {nome_immagine_locale} {cartella_dockerfile}',
        shell=True
    )

# Esegui il processo di automazione
build_docker_image()

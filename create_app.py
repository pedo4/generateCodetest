import subprocess

# Imposta i nomi delle risorse
nome_gruppo_risorse = 'srs2023-stu-g1'
nome_acr = 'srs2023.azurecr.io'
nome_immagine = 'samples/e_comm2'
app_service_plan = 'ASP-srs2023stug1-9160'

def login_azure():
    subprocess.run('az login', shell=True)

def create_webapp(nome_app_web):
    subprocess.run(
        f'az webapp create --name {nome_app_web} --resource-group {nome_gruppo_risorse} --plan {app_service_plan} --deployment-container-image {nome_acr}/{nome_immagine}',
        shell=True
    )

# Esegui il processo di automazione
login_azure()
nome_app_web = input("Inserisci il nome desiderato per la nuova app web: ")
create_webapp(nome_app_web)



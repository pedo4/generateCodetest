import subprocess

# Imposta i nomi delle risorse
nome_gruppo_risorse = 'srs2023-stu-g1'
nome_app_web = 'ProvaCont2'
image_id = 'srs2023.azurecr.io/samples/e_comm2'

def update_webapp_image(image_id):
    subprocess.run(
        f'az webapp config container set --name {nome_app_web} --resource-group {nome_gruppo_risorse} --docker-custom-image-name {image_id}',
        shell=True
    )

# Esegui il processo di automazione
update_webapp_image(image_id)


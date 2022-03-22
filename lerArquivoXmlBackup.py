
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

#Possivelmente ajustar esse código com ajuda de alguém
def lerArquivoXml2(dataAgora,usuario):
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
        for os in child.findall("os"):
            contador = 0
            for oss in os.findall("osmatch"):
                contador = contador + 1

                try:
                    so2 = SistemaOperacional.objects.get(nome = str(oss.attrib['name']))
                except:
                    so2 = SistemaOperacional.objects.create(nome = str(oss.attrib['name']))

                if contador == 1:
                    try:
                        Sistema_IP.objects.get(ip=str(title.attrib['addr']),
                                        )
                    except:
                        Sistema_IP.objects.create(ip=str(title.attrib['addr']),
                                              sistema=so2)

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
                        CVE_IP.objects.get(ip=str(title.attrib['addr']),
                                           cve = cve)
                    except:
                        CVE_IP.objects.create(ip=str(title.attrib['addr']),
                                           cve = cve)

    print(ip)
    print(portas)
    for i in range(len(ip)):
        print(ip[i])
        try:
            ipObjeto = IP.objects.get(ip=ip[i])
            ipObjeto.ativo = 1
            ipObjeto.save()
        except:
            if True == ipaddress.ip_address(ip[i]).is_private:
                redelocal = 1
            else:
                redelocal = 0


            ipObjeto = IP.objects.create(ip=ip[i],
                                             usuario=User.objects.get(username=usuario),
                                             ativo=1,
                                             redelocal = redelocal,
                                             )

        contador = - 1
        for portaVariavel in portas[i]:
            try:
                portaIp = Porta.objects.get(porta=int(portaVariavel), ip=IP.objects.get(ip=ip[i]))
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
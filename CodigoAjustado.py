#Codigo Ajustado
import xml.etree.ElementTree as ET
class LerArquivoXml2:
    def _init_(self, dataAgora, usuario):
        # Parse Arquivo
        print(usuario)
        self.usuario = usuario
        self.arvore = ET.parse(f"arquivos/nmap/{str(dataAgora)}{str(usuario)}.xml")
        self.infospcs = self.arvore.getroot()
    def listas(self):
        self.ip = []
        self.portas = []
        self.servicos = []
        self.produtos = []
        self.versoes = []
        self.sistemaoperacional_vai = []
        self.nomes_pegar_valores_nmap = ["name", "product", "version"]
    def enquerito_preenchimento(self):
        for pc in self.infospcs.findall("host"):
            for addr_info in pc.findall("address"):
                if addr_info.attrib['addrtype'] == 'ipv4':
                    self.ip.append(addr_info.attrib['addr'])
            for lista_portas_pc in pc.findall("ports"):
                for porta_do_pc in lista_portas_pc.findall("port"):

                    self.portas.append(porta_do_pc.attrib['portid'])

                    for serviço_da_porta in porta_do_pc.findall("service"):
                        self.servicos.append(serviço_da_porta.attrib['name'])
                        try:
                            self.produtos.append(serviço_da_porta.attrib['product'])
                        except:
                            self.produtos.append("Não existe")
                        try:
                            self.versoes.append(float(serviço_da_porta.attrib['version']))
                        except:
                            self.versoes.append(0)
            for so_info in pc.findall("os"):
                self.contador = 0

                for sistema_op in so_info.findall("osmatch"):
                    self.contador = self.contador + 1

                    try:
                        self.so2 = SistemaOperacional.objects.get(nome=str(sistema_op.attrib['name']))
                    except:
                        self.so2 = SistemaOperacional.objects.create(nome=str(sistema_op.attrib['name']))

                    if self.contador == 1:
                        try:
                            Sistema_IP.objects.get(ip=str(addr_info.attrib['addr']),
                                                   )
                        except:
                            Sistema_IP.objects.create(ip=str(addr_info.attrib['addr']),
                                                      sistema=self.so2)
            for script_info in pc.findall("hostscript"):
                for script in script_info.findall("script"):
                    for tabela_script in script.findall("table"):
                        try:
                            self.cve = CVE.objects.get(cve=str(tabela_script.attrib['key']))
                        except:
                            self.cve = CVE.objects.create(cve=str(tabela_script.attrib['key']))
                        try:
                            CVE_IP.objects.get(ip=str(addr_info.attrib['addr']),
                                               cve=self.cve)
                        except:
                            CVE_IP.objects.create(ip=str(addr_info.attrib['addr']),
                                                  cve=self.cve)
        print(self.ip)
        print(self.portas)
    def tratamento_ip(self):
        for index_ip in range(len(self.ip)):
            print(self.ip[index_ip])
            try:
                ipObjeto = IP.objects.get(ip=self.ip[index_ip])
                ipObjeto.ativo = 1
                ipObjeto.save()
            except:
                if True == ipaddress.ip_address(self.ip[index_ip]).is_private:
                    redelocal = 1
                else:
                    redelocal = 0
                ipObjeto = IP.objects.create(ip=self.ip[index_ip],
                                             usuario=User.objects.get(username=self.usuario),
                                             ativo=1,
                                             redelocal=redelocal,
                                             )
            self.contador = -1
            for portaVariavel in self.portas[index_ip]:
                try:
                    portaIp = Porta.objects.get(porta=int(portaVariavel), ip=IP.objects.get(ip=self.ip[index_ip]))
                    Porta.objects.create(porta=int(portaVariavel),
                                         ip=ipObjeto,
                                         servico=self.servicos[index_ip][self.contador],
                                         produto=self.produtos[index_ip][self.contador],
                                         versao=self.versoes[index_ip][self.contador],
                                         vulneravel=0,
                                         descricao="",
                                         tipo=0,
                                         ativo=0)
                    # portaIp = servicos[i][contador]
                except:
                    self.contador = self.contador + 1
                    Porta.objects.create(porta=int(portaVariavel),
                                         ip=ipObjeto,
                                         servico=self.servicos[index_ip][self.contador],
                                         produto=self.produtos[index_ip][self.contador],
                                         versao=self.versoes[index_ip][self.contador],
                                         vulneravel=0,
                                         descricao="",
                                         tipo=0)
    def nao_entendi(self):
        self.portas = Porta.objects.all()
        self.scanFalta = verificarScan()
        self.dados = {"portas": self.portas, "ips": self.ip,
                 "scans": self.scanFalta}
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models

class Rede(models.Model):
    rede = models.CharField(max_length=50)




class IP(models.Model):
    usuario = models.ForeignKey(User, models.CASCADE)
    rede = models.ForeignKey(Rede, models.CASCADE)
    ip = models.CharField(max_length=15)
    class redelocal(models.IntegerChoices):
        Redelocal = 0
        Internet = 1
    redelocal = models.IntegerField(default=0)

    class ativo(models.IntegerChoices):
        Desligado = 0
        Ativo = 1
    ativo = models.CharField(max_length=30)


    class Meta:
        ordering = ["ip"]
    def __str__(self):
        return (f'{self.ip} -{self.rede} ')

class Hostname(models.Model):
    hostname = models.CharField(max_length=50)
    def __str__(self):
        return (f'{self.hostname}')

class Hostname_IP(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    hostname = models.ForeignKey(Hostname, models.CASCADE)

    class exibir(models.IntegerChoices):
        Exibir = 1
    exibir = models.IntegerField(default=0)
class Scan(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    dataAgora = models.CharField(max_length=50)
    usuario = models.ForeignKey(User, models.CASCADE)
    feito = models.IntegerField(default=0)
    comando = models.CharField(max_length=200)

    def Data_Formato(self):
        try:
            vai = self.dataAgora.replace("-","/")[10:16]
            if ":"  == self.dataAgora.replace("-", "/")[10:16][-1:]:
                vai = self.dataAgora.replace("-","/")[10:15]


            return (f'{self.dataAgora.replace("-","/")[0:10]} {vai}')
        except:
            return self.dataAgora


class FfufComandos(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    dataAgora = models.CharField(max_length=31)
    usuario = models.ForeignKey(User, models.CASCADE)
    feito = models.IntegerField(default=0)
    comando = models.CharField(max_length=300)
    porta = models.IntegerField(validators=[MinValueValidator(1),
                                            MaxValueValidator(65536)])

    def __str__(self):
        return self.comando

class Diretorios(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    porta = models.IntegerField(validators=[MinValueValidator(1),
                                            MaxValueValidator(65536)])
    path = models.CharField(max_length=100)
    http_code = models.IntegerField(validators=[MinValueValidator(1),
                                            MaxValueValidator(1000)])


    def __str__(self):
        return f'{self.ip.ip}:{self.porta}{self.path}'
class QueryParameteres(models.Model):
    diretorio = models.ForeignKey(Diretorios, models.CASCADE)

    parametro = models.CharField(max_length=100)
    valor = models.CharField(max_length=100)
    vulneravel = models.IntegerField(default=0)


class Porta(models.Model):
    porta = models.IntegerField()
    ip = models.ForeignKey(IP, models.CASCADE)
    servico = models.CharField(max_length=50)

    produto = models.CharField(max_length=50)
    versao = models.CharField(max_length=50)
    vulneravel = models.IntegerField()

    class tipo(models.IntegerChoices):
        Baixa = 1
        Intermediaria = 2
        Alta = 3
        Critica = 4
        Segura = 0




    tipo = models.IntegerField(default=0)
    ativo = models.IntegerField(default=1)

    status = models.CharField(max_length=30)

    def get_Tipo(self):
        lugares_envio = {
            '1': 'Baixa',
            '2': 'Intermediaria',
            '3': 'Alta',
            '4': 'Crítica',
            '0': 'Segura'
        }
        return lugares_envio.get(str(self.tipo), str(self.tipo))

    data_evento = models.DateTimeField(auto_now=True)

    def get_91days(self):
        from datetime import timedelta
        return self.data_evento + timedelta(days=91)
    descricao = models.CharField(max_length=50)
    def __str__(self):
        return (f'{self.ip.ip}:{self.porta} -{self.ip.rede}:{self.ativo}')

class CVE(models.Model):
    cve = models.CharField(max_length=50)

    def __str__(self):
        return self.cve

class CVE_IP(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    cve = models.ForeignKey(CVE, models.CASCADE)
    descricao = models.CharField(max_length=500)
    vulneravel = models.IntegerField(default=0)
    titulo = models.CharField(max_length=500)


class Pentest(models.Model):
    nome = models.CharField(max_length=50)
    class tipo(models.IntegerChoices):
        Web = 1
        Infraestrutura = 2
    tipo = models.IntegerField(default=0)

    automatico = models.IntegerField(default=0)

    imagem = models.ImageField(upload_to='static/pentests', blank=True)

class Pentest_Rede(models.Model):
    rede = models.ForeignKey(Rede, models.CASCADE)
    pentest = models.ForeignKey(Pentest, models.CASCADE)
    usuario = models.ForeignKey(User, models.CASCADE)




class SistemaOperacional(models.Model):
    nome = models.CharField(max_length=50)

    def __str__(self):
        return self.nome
class Sistema_IP(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    sistema = models.ForeignKey(SistemaOperacional, models.CASCADE)
    probabilidade =  models.DecimalField(max_digits=10, decimal_places=5,default=0)
    posicao =   models.IntegerField(default=0)

    def __str__(self):
        return self.sistema.nome


class WhatWeb(models.Model):
    Titulo = models.CharField(max_length=50)

class WhatWebIP(models.Model):
    whatweb = models.ForeignKey(WhatWeb, models.CASCADE)
    nome = models.CharField(max_length=50)
    valor = models.CharField(max_length=50)
    ip = models.ForeignKey(IP, models.CASCADE)


class WhatWebComandos(models.Model):
    diretorio = models.ForeignKey(Diretorios, models.CASCADE)
    feito = models.IntegerField(default=0)
    arquivo = models.CharField(max_length=200)



class Dominio(models.Model):
    nome = models.CharField(max_length=50)
    ip = models.ForeignKey(IP, models.CASCADE)

    def __str__(self):
        return self.nome

class inetNum(models.Model):
    ipMinimo_ip = models.ForeignKey(IP, models.CASCADE, related_name="minimo")
    ipMaximo_ip = models.ForeignKey(IP, models.CASCADE, related_name="maximo")


class dominioinetNum(models.Model):
    Dominio = models.ForeignKey(Dominio, models.CASCADE)
    bloco = models.ForeignKey(inetNum, models.CASCADE)


class spfDominio(models.Model):
    Dominio = models.ForeignKey(Dominio, models.CASCADE)
    vulneravel = models.IntegerField()
    # 0 É VULNERAVEL, 1 É TRATADO COMO SUSPEITO E 2 NÃO É VULNERAVEL
    descricao = models.CharField(max_length=50)


class Emails(models.Model):
    email = models.CharField(max_length=50)
    Dominio = models.ForeignKey(Dominio, models.CASCADE)


class SenhaMsfConsole(models.Model):
    senha = models.CharField(max_length=50)



class SubDominio(models.Model):
    Dominio = models.ForeignKey(Dominio, models.CASCADE)
    host = models.CharField(max_length=50)
    ip = models.ForeignKey(IP, models.CASCADE)


class ExploitRodar(models.Model):

    nome = models.CharField(max_length=200)
    exploit = models.CharField(max_length=100)
    payload = models.CharField(max_length=100)
    feito = models.IntegerField(default=0)


class Exploit_Payload(models.Model):
    exploit = models.ForeignKey(ExploitRodar, models.CASCADE)
    nome = models.CharField(max_length=200)
    conteudo = models.CharField(max_length=200)
    tipo = models.IntegerField(default=0)


class SqlComandos(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    dataAgora = models.CharField(max_length=32)
    usuario = models.ForeignKey(User, models.CASCADE)
    feito = models.IntegerField(default=0)
    comando = models.CharField(max_length=300)
    porta = models.IntegerField(validators=[MinValueValidator(1),
                                            MaxValueValidator(65536)])
    diretorio = models.ForeignKey(Diretorios, models.CASCADE)

    def __str__(self):
        return self.comando


class Vulnerabilidades_Definicoes(models.Model):
    nome = models.CharField(max_length=50)
    descricao = models.CharField(max_length=500)


class Vulnerabilidades(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    porta = models.ForeignKey(Porta, models.CASCADE)
    tipo = models.ForeignKey(Vulnerabilidades_Definicoes, models.CASCADE)
    path = models.CharField(max_length=50)
    parametro = models.CharField(max_length=50)
    CVSS = models.CharField(max_length=100)
    impacto = models.CharField(max_length=500)
    recomendacao = models.CharField(max_length=500)
    tratada = models.IntegerField(default=0)
    grau = models.CharField(max_length=30,default="VULNERABLE")

    def getIntegerTratar(self):
        try:
            return int(self.CVSS.split(" ")[0])
        except:
            return self.CVSS


class Vulnerabilidades_Referencias(models.Model):
    Vulnerabilidades = models.ForeignKey(Vulnerabilidades, models.CASCADE)
    referencia = models.CharField(max_length=500)



class Etapas(models.Model):
    dominio = models.CharField(max_length=100)
    assunto = models.ForeignKey(Pentest_Rede, models.CASCADE)
    ip = models.ForeignKey(IP, models.CASCADE)

    def __str__(self):
        return self.ip.ip


class Plugin(models.Model):
    nome_arquivo = models.CharField(max_length=100)

"""
class Plugin_Scan(models.Model):
    plugin = models.ForeignKey(Plugin, models.CASCADE)
    class tipo(models.IntegerChoices):
        ip = 0
        Internet = 1
    tipo = models.IntegerField(default=0)
"""
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
    ativo = models.IntegerField(default=0)

    def __str__(self):
        return self.ip
    class Meta:
        ordering = ["ip"]


class Scan(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    dataAgora = models.CharField(max_length=50)
    usuario = models.ForeignKey(User, models.CASCADE)
    feito = models.IntegerField(default=0)
    comando = models.CharField(max_length=200)




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
        return f'{self.ip}:{self.porta}{self.path}'

class Porta(models.Model):
    porta = models.IntegerField()
    ip = models.ForeignKey(IP, models.CASCADE)
    servico = models.CharField(max_length=50)

    produto = models.CharField(max_length=50)
    versao = models.DecimalField(max_digits=10, decimal_places=5)
    vulneravel = models.IntegerField()

    class tipo(models.IntegerChoices):
        Baixa = 1
        Intermediaria = 2
        Alta = 3
        Critica = 4
        Segura = 0




    tipo = models.IntegerField(default=0)
    ativo = models.IntegerField(default=1)

    def get_Tipo(self):
        lugares_envio = {
            '1': 'Baixa',
            '2': 'Intermediaria',
            '3': 'Alta',
            '4': 'Crítica',
            '0': 'Segura'
        }
        return lugares_envio.get(str(self.tipo), str(self.tipo))

    descricao = models.CharField(max_length=50)


class CVE(models.Model):
    cve = models.CharField(max_length=50)

    def __str__(self):
        return self.cve

class CVE_IP(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    cve = models.ForeignKey(CVE, models.CASCADE)


class Pentest(models.Model):
    nome = models.CharField(max_length=50)
    class tipo(models.IntegerChoices):
        Web = 1
        Infraestrutura = 2
    tipo = models.IntegerField(default=0)

    automatico = models.IntegerField(default=0)


class Pentest_Rede(models.Model):
    rede = models.ForeignKey(Rede, models.CASCADE)
    pentest = models.ForeignKey(Pentest, models.CASCADE)
    usuario = models.ForeignKey(User, models.CASCADE)




class SistemaOperacional(models.Model):
    nome = models.CharField(max_length=50)


class Sistema_IP(models.Model):
    ip = models.ForeignKey(IP, models.CASCADE)
    sistema = models.ForeignKey(SistemaOperacional, models.CASCADE)
from django.contrib import admin

from core.models import Scan,Diretorios,IP,Rede,FfufComandos,Sistema_IP,SistemaOperacional,CVE,CVE_IP,Pentest,Pentest_Rede,Porta



admin.site.register(Scan)

admin.site.register(Diretorios)
admin.site.register(FfufComandos)
admin.site.register(IP)
admin.site.register(Rede)

admin.site.register(Sistema_IP)
admin.site.register(SistemaOperacional)
admin.site.register(CVE)
admin.site.register(CVE_IP)
admin.site.register(Pentest)
admin.site.register(Pentest_Rede)
admin.site.register(Porta)








# Register your modelpythos here.

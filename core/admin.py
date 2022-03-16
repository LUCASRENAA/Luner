from django.contrib import admin

from core.models import Scan,Diretorios,IP,Rede,FfufComandos,Sistema_IP,SistemaOperacional,CVE,CVE_IP,Pentest,Pentest_Rede,Porta

from core.models import WhatWebComandos,WhatWeb,WhatWebIP,Dominio,inetNum,dominioinetNum,spfDominio,SenhaMsfConsole,SubDominio

from core.models import ExploitRodar,Exploit_Payload,QueryParameteres,SqlComandos,Etapas,Vulnerabilidades
admin.site.register(ExploitRodar)
admin.site.register(Exploit_Payload)
admin.site.register(QueryParameteres)

admin.site.register(SqlComandos)
admin.site.register(Vulnerabilidades)

admin.site.register(Etapas)


admin.site.register(Dominio)
admin.site.register(inetNum)
admin.site.register(dominioinetNum)
admin.site.register(spfDominio)

admin.site.register(Scan)
admin.site.register(WhatWebComandos)
admin.site.register(WhatWeb)
admin.site.register(WhatWebIP)

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

admin.site.register(SenhaMsfConsole)

admin.site.register(SubDominio)




# Register your modelpythos here.

from django.contrib import admin

from core.models import Scan,Diretorios,IP,Rede,FfufComandos,Sistema_IP,SistemaOperacional,CVE,CVE_IP,Pentest,Pentest_Rede,Porta

from core.models import WhatWebComandos,WhatWeb,WhatWebIP,Dominio,inetNum,dominioinetNum,spfDominio,SenhaMsfConsole,SubDominio

from core.models import ExploitRodar,Exploit_Payload,\
    QueryParameteres,SqlComandos,Etapas,Vulnerabilidades,\
    Vulnerabilidades_Definicoes,Hostname,Hostname_IP,Checklist,Ataque,Defesa,Hash_Senha_Cofre,\
    ChecklistRede,PostagensForum,EvidenciaCheckList
admin.site.register(Checklist)
admin.site.register(Ataque)
admin.site.register(Defesa)
admin.site.register(ChecklistRede)
admin.site.register(PostagensForum)
admin.site.register(EvidenciaCheckList)


admin.site.register(Hash_Senha_Cofre)
admin.site.register(ExploitRodar)
admin.site.register(Exploit_Payload)
admin.site.register(QueryParameteres)
admin.site.register(Hostname)
admin.site.register(Hostname_IP)

admin.site.register(SqlComandos)
admin.site.register(Vulnerabilidades)

admin.site.register(Etapas)
admin.site.register(Vulnerabilidades_Definicoes)


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

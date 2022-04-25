"""controle_estoque URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from core import views
from django.views.generic import RedirectView
urlpatterns = [
    path('admin/', admin.site.urls),
    path('registro/', views.registro),
                  path('exploit/', views.exploit),
                  path('exploit2/', views.ligarMetaSploi),
                  path('exploit3/<sessao>', views.exploit3),

                  path('exploit/procurar/', views.procurarExploits),
                  path('exploit/procurar/exploit', views.usandoExploit),
                  path('exploit/procurar/exploit/rodar', views.rodandoExploit),
                  path('exploit/procurar/exploit/rodar/rodar/', views.rodandoExploitCerto),

                  path('rodarExploits/', views.verExploitsRodar),
                  path('rodar/<id>', views.rodar),

                  path('dominio2/<dominio>/<rede_vpn>', views.publicoDominio),
                  path('dominio2/ver/<dominio>/<rede>', views.verDominio),

                  path('spf/<dominio>/<rede_vpn>', views.SPF),
                  path('emails/<dominio>/<rede_vpn>', views.EmailsFuncao),
                  path('theHarvester/<dominio>/<rede_vpn>', views.theHarvester),

                  path('registro/submit', views.submit_registro),

                  path('rede/', views.rede),
                  path('whatweb/<id>', views.whatweb),
                  path('parserSite/<id>', views.parserSite),
                  path('sqlmap/<id>', views.sqlmap),

                  path('inicio/<rede>',views.inicio),
                  path('scan/<id>', views.scan_id_historico),
                  path('scan/', views.scan_historico),


                  path('inicio/scanopcao/ip/rede', views.scanOpcoes),
                  path('inicio/dirb/ip/rede', views.dirbOpcoes),

                  path('login/', views.login_user),
    path('login/submit',views.submit_login),

                  path('inicio/', RedirectView.as_view(url='/inicio/WQFQWFUQWHFQWHFQWHFIWIF')),
              path('handle_xml_upload/', views.handle_xml_upload),

              path('dominio', views.cursos),
                  path('dominio/<id>', views.assunto),
                  path('dominio/<id>/<ip>', views.assunto_ip),
                  #path('pdf', views.pdfteste),

                  path('',RedirectView.as_view(url='rede/'))
]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

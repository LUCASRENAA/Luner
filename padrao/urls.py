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

from django.urls import path, include
from django.contrib.auth.models import User
from rest_framework import routers, serializers, viewsets
from core.views import VulnerabilidadesViewSet

# Serializers define the API representation.
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'is_staff']

# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register('vulnerabilidades', VulnerabilidadesViewSet, basename='vulnerabilidades')

urlpatterns = [
    path('admin/', admin.site.urls),
    path('registro/', views.registro),
                  path('logout/', views.logout_user),

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

                  path('ataque/', views.ataque),
                  path('ataque/<id>', views.ataqueId),
                  path('ataque/rede/<rede>', views.ataque_rede),

                  path('defesa/', views.defesa),

                  path('rede/', views.rede),
                  path('whatweb/<id>', views.whatweb),
                  path('parserSite/<id>', views.parserSite),
                  path('sqlmap/<id>', views.sqlmap),

                  path('inicio/<rede>',views.inicio),
                  path('inicio_tabelas/<rede>', views.inicio_tabelas),

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
                  path('relatoriocompleto/<id>', views.relatorio_completo),

                  path('dominio/<id>/<ip>', views.assunto_ip),
                  #path('pdf', views.pdfteste),
                  path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),

                  path('api/', include(router.urls)),
                  path('', RedirectView.as_view(url='rede/')),

                  path('cofre/', views.cofre),

                  path('cofre/submit', views.cofre_submit),
                  path('upload/', views.subir_arquivo),
                  path('baixar/<id>', views.descer_arquivo_path),

                  path('ataque/rede/<rede>', views.ataque_rede),
                  path('ataque/rede/', RedirectView.as_view(url='/ataque/rede/WQFQWFUQWHFQWHFQWHFIWIF')),
                  path('selecionartexto/<id>', views.selecionar_texto),
                  path('descriptografar_texto/', views.descriptografar_texto),

                  path('criptografar_texto/', views.criptografar_texto_submit),
                  path('forum/<id>/', views.forum),
                  path('forum/<id>/submit', views.submitFotoEvidencia),

                  path('vulnerabilidade/id/<id>/', views.comunidade),
                  path('vulnerabilidade/id/<id>/submit', views.comunidade_vuln),

                  path('vulnerabilidade/mudar/<id>/submit', views.mudarTratamentoVuln),

              ]+ static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

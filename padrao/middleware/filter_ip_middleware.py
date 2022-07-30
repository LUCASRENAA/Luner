from datetime import datetime, timezone, timedelta

from admin_honeypot.models import LoginAttempt
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin


class FiltraIPMiddleware(MiddlewareMixin):

  def _init_(self, get_response=None):
    self.get_response = get_response

  def _call_(self, request):
    response = self.get_response(request)

    return response


  def process_view(self,request, func, args, kwargs):
    # Lista de IPs autorizados
    ips_nao_autorizados = []
    try:
      for logins in  LoginAttempt.objects.all():
        print(logins.ip_address)
        start_time = logins.timestamp
        periodo_por_dias = 4
        delete_time = datetime.now(tz=timezone.utc) - timedelta(days=periodo_por_dias)
        print(delete_time>start_time)
        if delete_time < start_time:
          continue
        else:
          ips_nao_autorizados.append(logins.ip_address)
    except:
      pass


    # IP do usuário
    ip = request.META.get('REMOTE_ADDR')

    # Verifica se o IP do cliente está na lista de IPs autorizados
    if ip  in ips_nao_autorizados:
      # Se usuário não autorizado > HTTP 403: Não Autorizado
      return HttpResponseForbidden("IP não autorizado")

    # Se for autorizado, não fazemos nada
    return None
from datetime import datetime, timezone, timedelta

from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin

from core.views import xmlBancoVerificar, dirbBancoVerificar, WhatWebVerificar, LigarMetaexploit, sqlmapVerificar, \
  deletarImagens


class VerificarScan(MiddlewareMixin):

  def _init_(self, get_response=None):
    self.get_response = get_response

  def _call_(self, request):
    response = self.get_response(request)

    return response


  def process_view(self,request, func, args, kwargs):
    # Lista de IPs autorizados
    a = xmlBancoVerificar()


    b = dirbBancoVerificar()
    b = sqlmapVerificar()

    c = WhatWebVerificar()
    d = LigarMetaexploit()
    e = deletarImagens()
    return None
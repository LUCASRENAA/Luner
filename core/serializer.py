from rest_framework import serializers

from core.models import Vulnerabilidades


class VulnerabilidadesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerabilidades
        fields = '__all__'


# Generated by Django 3.0.7 on 2022-03-22 08:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0036_cve_ip_descricao'),
    ]

    operations = [
        migrations.RenameField(
            model_name='sistema_ip',
            old_name='ativo',
            new_name='posicao',
        ),
    ]

# Generated by Django 3.0.7 on 2022-04-29 03:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0043_auto_20220428_1819'),
    ]

    operations = [
        migrations.AddField(
            model_name='hostname_ip',
            name='exibir',
            field=models.IntegerField(default=0),
        ),
    ]
# Generated by Django 3.2.10 on 2022-05-25 01:16

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0051_auto_20220525_0114'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='checklistrede',
            name='name',
        ),
        migrations.RemoveField(
            model_name='checklistrede',
            name='parent',
        ),
    ]

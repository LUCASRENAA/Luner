# Generated by Django 3.2.10 on 2022-05-25 01:16

from django.db import migrations, models
import django.db.models.deletion
import mptt.fields


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0052_auto_20220525_0116'),
    ]

    operations = [
        migrations.AddField(
            model_name='checklistrede',
            name='name',
            field=models.CharField(default=1, max_length=50, unique=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='checklistrede',
            name='parent',
            field=mptt.fields.TreeForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='children', to='core.checklistrede'),
        ),
    ]

# Generated by Django 3.2.12 on 2023-03-30 18:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('drp_pip', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='authorizedagent',
            name='bearer_token',
            field=models.TextField(blank=True, verbose_name='pair-wise token between AA and CB'),
        ),
    ]
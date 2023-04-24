# Generated by Django 3.2.12 on 2023-04-24 19:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('drp_pip', '0004_auto_20230404_1719'),
    ]

    operations = [
        migrations.AddField(
            model_name='authorizedagent',
            name='business_contact',
            field=models.TextField(blank=True, verbose_name='Email address to contact for business/legal communiques'),
        ),
        migrations.AddField(
            model_name='authorizedagent',
            name='identity_assurance_url',
            field=models.TextField(blank=True, verbose_name="Link to document describing the Agent's identity assurance standards"),
        ),
        migrations.AddField(
            model_name='authorizedagent',
            name='technical_contact',
            field=models.TextField(blank=True, verbose_name='Email address to contact for technical issues'),
        ),
        migrations.AddField(
            model_name='authorizedagent',
            name='web_url',
            field=models.TextField(blank=True, verbose_name="Authorized Agent's home page"),
        ),
    ]

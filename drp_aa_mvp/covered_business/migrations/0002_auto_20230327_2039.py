# Generated by Django 3.2.12 on 2023-03-27 20:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('covered_business', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='coveredbusiness',
            name='signing_key',
            field=models.CharField(blank=True, default='', max_length=127),
        ),
        migrations.AddField(
            model_name='coveredbusiness',
            name='verify_key',
            field=models.CharField(blank=True, default='', max_length=4096),
        ),
    ]

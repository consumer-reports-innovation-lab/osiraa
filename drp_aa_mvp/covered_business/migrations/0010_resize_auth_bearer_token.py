# Generated by Django 3.2.12 on 2022-08-19 17:14

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('covered_business', '0009_alter_coveredbusiness_supported_actions'),
    ]

    operations = [
        migrations.AlterField(
            model_name='coveredbusiness',
            name='auth_bearer_token',
            field=models.CharField(blank=True, default='', max_length=4096),
        ),
    ]

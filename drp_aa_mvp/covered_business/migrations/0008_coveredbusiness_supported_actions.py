# Generated by Django 4.0.4 on 2022-08-16 15:38

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('covered_business', '0007_rename_api_endpoint_coveredbusiness_api_root_endpoint_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='coveredbusiness',
            name='supported_actions',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=31), default=list, size=None),
        ),
    ]

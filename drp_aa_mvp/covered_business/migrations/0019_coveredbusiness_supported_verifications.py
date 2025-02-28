# Generated by Django 3.2.12 on 2025-01-27 20:00

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('covered_business', '0018_remove_coveredbusiness_api_endpoint'),
    ]

    operations = [
        migrations.AddField(
            model_name='coveredbusiness',
            name='supported_verifications',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(choices=[('address', 'address'), ('eamil', 'EMAIL'), ('phone_number', 'phone_number')], max_length=31), default=list, size=None),
        ),
    ]

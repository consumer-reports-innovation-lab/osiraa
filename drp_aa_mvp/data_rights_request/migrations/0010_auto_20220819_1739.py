# Generated by Django 3.2.12 on 2022-08-19 17:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data_rights_request', '0009_auto_20220819_1735'),
    ]

    operations = [
        migrations.AddField(
            model_name='datarightsstatus',
            name='expected_by',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='datarightsstatus',
            name='received_at',
            field=models.DateTimeField(null=True),
        ),
        migrations.AddField(
            model_name='drprequesttransaction',
            name='expires_date',
            field=models.DateTimeField(null=True),
        ),
    ]

# Generated by Django 3.2.12 on 2022-08-19 17:35

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('data_rights_request', '0008_auto_20220819_1721'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='datarightsrequest',
            name='identity',
        ),
        migrations.DeleteModel(
            name='IdentityPayload',
        ),
    ]

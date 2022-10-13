# Generated by Django 3.2.12 on 2022-08-19 17:41

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('data_rights_request', '0010_auto_20220819_1739'),
    ]

    operations = [
        migrations.CreateModel(
            name='IdentityPayload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('issuer', models.TextField(blank=True, default='', max_length=255)),
                ('audience', models.TextField(blank=True, default='', max_length=255)),
                ('subject', models.TextField(blank=True, default='', max_length=255)),
                ('name', models.TextField(blank=True, default='', max_length=255)),
                ('email', models.EmailField(blank=True, default='', max_length=255)),
                ('email_verified', models.BooleanField(default=False)),
                ('phone_number', models.TextField(blank=True, default='', max_length=15)),
                ('phone_number_verified', models.BooleanField(default=False)),
                ('address', models.EmailField(blank=True, default='', max_length=255)),
                ('address_verified', models.BooleanField(default=False)),
                ('power_of_attorney', models.EmailField(blank=True, default='', max_length=255)),
            ],
        ),
        migrations.AddField(
            model_name='datarightsrequest',
            name='identity',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='data_rights_request.identitypayload'),
        ),
    ]

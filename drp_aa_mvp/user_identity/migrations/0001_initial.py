# Generated by Django 3.2.12 on 2025-01-03 20:53

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='IdentityUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(blank=True, default='', max_length=63)),
                ('last_name', models.CharField(blank=True, default='', max_length=63)),
                ('email', models.EmailField(blank=True, default='', max_length=127)),
                ('email_verified', models.BooleanField(default=False)),
                ('phone_number', models.CharField(blank=True, default='', max_length=15)),
                ('phone_verified', models.BooleanField(default=False)),
                ('city', models.CharField(blank=True, default='', max_length=63)),
                ('country', models.CharField(blank=True, default='', max_length=63)),
                ('address1', models.CharField(blank=True, default='', max_length=127)),
                ('address2', models.CharField(blank=True, default='', max_length=127)),
                ('state_province', models.CharField(blank=True, default='', max_length=2)),
                ('zip_postal', models.CharField(blank=True, default='', max_length=5)),
                ('address_verified', models.BooleanField(default=False)),
                ('power_of_attorney', models.BooleanField(default=False)),
            ],
        ),
    ]

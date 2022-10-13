# Generated by Django 4.0.4 on 2022-05-03 18:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('covered_business', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CoveredBusiness',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('logo', models.ImageField(upload_to='company-logos', verbose_name='Logo Image')),
                ('logo_thumbnail', models.ImageField(upload_to='company-logos/thumbnails')),
                ('subtitle_description', models.TextField()),
                ('request_email', models.EmailField(max_length=254)),
                ('is_internal_email', models.BooleanField(default=False)),
                ('opt_out_details', models.TextField(blank=True)),
                ('delete_data_details', models.TextField(blank=True)),
                ('request_description', models.TextField(blank=True)),
            ],
        ),
        migrations.DeleteModel(
            name='Company',
        ),
    ]

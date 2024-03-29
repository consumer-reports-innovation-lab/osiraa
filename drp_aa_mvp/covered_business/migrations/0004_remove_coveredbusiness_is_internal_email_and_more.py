# Generated by Django 4.0.4 on 2022-05-03 18:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('covered_business', '0003_coveredbusiness_brand_name_coveredbusiness_name'),
    ]

    operations = [
        migrations.AlterField(
            model_name='coveredbusiness',
            name='logo',
            field=models.ImageField(blank=True, upload_to='company-logos', verbose_name='Logo Image'),
        ),
        migrations.AlterField(
            model_name='coveredbusiness',
            name='logo_thumbnail',
            field=models.ImageField(blank=True, upload_to='company-logos/thumbnails'),
        ),
        migrations.AlterField(
            model_name='coveredbusiness',
            name='subtitle_description',
            field=models.TextField(blank=True),
        ),
    ]

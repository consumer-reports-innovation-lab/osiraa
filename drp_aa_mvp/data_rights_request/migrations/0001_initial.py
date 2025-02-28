# Generated by Django 3.2.12 on 2025-01-03 20:53

import django.contrib.postgres.fields
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('covered_business', '0001_initial'),
        ('user_identity', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DataRightsRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('request_id', models.TextField(blank=True, default='', max_length=255)),
                ('relationships', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=31), default=list, size=None)),
                ('status_callback', models.URLField(blank=True, default='', max_length=1023)),
                ('regime', models.CharField(choices=[('ccpa', 'ccpa'), ('voluntary', 'voluntary')], default='ccpa', max_length=31)),
                ('right', models.CharField(choices=[('opt_out', 'sale:opt-out'), ('opt_in', 'sale:opt-in'), ('access', 'access'), ('deletion', 'deletion'), ('access_cat', 'access:categories '), ('access_spec', 'access:specific ')], default=None, max_length=31)),
            ],
        ),
        migrations.CreateModel(
            name='DataRightsStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('request_id', models.TextField(blank=True, default='', max_length=255)),
                ('received_at', models.DateTimeField(null=True)),
                ('results_url', models.URLField(blank=True, default='', max_length=255)),
                ('expected_by', models.DateTimeField(null=True)),
                ('processing_details', models.TextField(blank=True, default='', max_length=1023, null=True)),
                ('status', models.TextField(blank=True, choices=[('in_progress', 'in_progress'), ('open', 'open'), ('fulfilled', 'fulfilled'), ('revoked', 'revoked'), ('denied', 'denied'), ('expired', 'expired')], default='', max_length=31)),
                ('reason', models.TextField(blank=True, choices=[('need_user_verification', 'need_user_verification'), ('suspected_fraud', 'suspected_fraud'), ('insufficient_verification', 'insufficient_verification'), ('no_match', 'no_match'), ('claim_not_covered', 'claim_not_covered'), ('outside_jurisdiction', 'outside_jurisdiction'), ('other', 'other'), ('', '')], default='', max_length=31, null=True)),
                ('user_verification_url', models.URLField(blank=True, default='', max_length=127, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='IdentityPayload',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('issuer', models.TextField(blank=True, default='', max_length=127)),
                ('audience', models.TextField(blank=True, default='', max_length=127)),
                ('subject', models.TextField(blank=True, default='', max_length=127)),
                ('name', models.TextField(blank=True, default='', max_length=127)),
                ('email', models.EmailField(blank=True, default='', max_length=127)),
                ('email_verified', models.BooleanField(default=False)),
                ('phone_number', models.TextField(blank=True, default='', max_length=15)),
                ('phone_number_verified', models.BooleanField(default=False)),
                ('address', models.EmailField(blank=True, default='', max_length=127)),
                ('address_verified', models.BooleanField(default=False)),
                ('power_of_attorney', models.EmailField(blank=True, default='', max_length=127)),
            ],
        ),
        migrations.CreateModel(
            name='DrpRequestTransaction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('request_id', models.TextField(blank=True, default='', max_length=255)),
                ('current_status', models.TextField(blank=True, choices=[('in_progress', 'in_progress'), ('open', 'open'), ('fulfilled', 'fulfilled'), ('revoked', 'revoked'), ('denied', 'denied'), ('expired', 'expired')], default='', max_length=31)),
                ('expires_date', models.DateTimeField(null=True)),
                ('is_final', models.BooleanField(default=False)),
                ('company_ref', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='covered_business.coveredbusiness')),
                ('user_ref', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='user_identity.identityuser')),
            ],
        ),
        migrations.CreateModel(
            name='DrpRequestStatusPair',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('request_ref', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='data_rights_request.datarightsrequest')),
                ('response_ref', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='data_rights_request.datarightsstatus')),
            ],
        ),
        migrations.AddField(
            model_name='datarightsrequest',
            name='identity',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='data_rights_request.identitypayload'),
        ),
    ]

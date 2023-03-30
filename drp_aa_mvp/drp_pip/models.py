from django.db import models

class AuthorizedAgent(models.Model):
    name                  = models.CharField(max_length=63, blank=True, default='')
    brand_name            = models.CharField(max_length=63, blank=True, default='')
    aa_id                 = models.CharField(max_length=63, blank=True, default='')
    logo                  = models.ImageField('Logo Image', upload_to='company-logos', blank=True)
    logo_thumbnail        = models.ImageField(upload_to='company-logos/thumbnails', blank=True)
    subtitle_description  = models.TextField(blank=True)

    verify_key            = models.TextField('Hex encoded key to verify signed requests')
    bearer_token          = models.TextField('pair-wise token between AA and CB', blank=True)

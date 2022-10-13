from django.db import models

#from .base import AbstractEmailUser
#from libs.models import UUIDModel
#from phonenumber_field.modelfields import PhoneNumberField
#from django_countries.fields import CountryField


class IdentityUser(models.Model): #(AbstractEmailUser, UUIDModel):
    first_name          = models.CharField(max_length=63, blank=True, default='')
    last_name           = models.CharField(max_length=63, blank=True, default='')
    email               = models.EmailField(max_length=127, blank=True, default='')
    email_verified      = models.BooleanField(default=False)
    phone_number        = models.CharField(max_length=15, blank=True, default='')
    phone_verified      = models.BooleanField(default=False)
    city                = models.CharField(max_length=63, blank=True, default='')
    country             = models.CharField(max_length=63, blank=True, default='')
    address1            = models.CharField(max_length=127, blank=True, default='')
    address2            = models.CharField(max_length=127, blank=True, default='')
    state_province      = models.CharField(max_length=2, blank=True, default='')
    zip_postal          = models.CharField(max_length=5, blank=True, default='')
    address_verified    = models.BooleanField(default=False)
    power_of_attorney   = models.BooleanField(default=False)

    #signature_s3_key = models.TextField(blank=True)
    #date_signed = models.DateTimeField(null=True)

    def __str__(self):
        return (self.last_name + ', ' + self.first_name)

    #todo: return full_name, full_address    
 
# -*- coding: utf-8 -*-


from django.db import models
#from django.contrib.auth.models import AbstractUser
class Role(models.Model):
    name = models.CharField(max_length=100, primary_key=True)
    role = models.CharField(max_length=2)

class OperationLog(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    datetime = models.DateTimeField(auto_now = True)
    operation = models.TextField(null=True, blank=True, default="")
    status = models.CharField(max_length=10, default="success")
    detail = models.TextField(null=True, blank=True, default="")
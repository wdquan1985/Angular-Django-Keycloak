# -*- coding: utf-8 -*-
from rest_framework import serializers
from django.contrib.auth.models import User
from users.models import Role
from users.models import OperationLog

# Serializers define the API representation.
class RoleSerializer(serializers.ModelSerializer):

    def create(self, validated_data):
        instance = Role(**validated_data)
        instance.save()
        return instance

    def update(self, instance, validated_data):
        instance.name = validated_data['name']
        instance.role = validated_data['role']
        instance.save()
        return instance

    class Meta:
        model = Role
        fields = ('name','role')


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email')

# Serializers define the API representation.
class OperationLogSerializer(serializers.ModelSerializer):

    def create(self, validated_data):
        instance = OperationLog(**validated_data)
        instance.save()
        return instance

    def update(self, instance, validated_data):
        instance.name = validated_data['name']
        instance.operation = validated_data['operation']
        instance.status = validated_data['status']
        instance.detail = validated_data['detail']
        instance.save()
        return instance

    class Meta:
        model = OperationLog
        fields = ('id','name','datetime','operation','status','detail')
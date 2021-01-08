
import logging
from urllib.parse import quote

import requests
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from requests_oauthlib import OAuth2Session
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed, NotAuthenticated
import json
from django.views.decorators.csrf import csrf_exempt

from users.KeyclaokHttpRequest import KeycloakHttpRequest

#from django.http.response import JsonResponse
from rest_framework.response import Response
from rest_framework.views import APIView

class AdminView(APIView):
    keycloak_scopes = {'GETs': 'read-only-admin-view', 'POSTs': 'edit-admin-view', 'DEFAULTs': 'default-admin-view'}

    def get(self, request, **kwargs):
        #print("Debug: the request user is " + str(request.user))
        #print("Debug: the request user id is " + str(request.user.id))
        #print("Debug: the request user email is " + str(request.user.email))
        #print("Debug: the request user name is " + str(request.user.username))
        # user_roles = request.META.get('USER_ROLES').split(',')
        # print("Debug: the USER_ROLES in request headers is: " + str(user_roles))

        # print("Debug: the value of is_authenticated is: " + request.user.username)
        #user_groups = request.META.get('USER_GROUPS').split(',')
        #print("Debug: the USER_GROUPS in request headers is: " + str(user_groups))
        #print("Debug: the USER_ROLES in request headers is: " + user_roles[0])
        return Response(data={"page": "Admin Resource 1"},status=200)

    def post(self, request, format=None):
        return Response(data={"page": "Edit Admin Resource"},status=200)

class KeycloakTokenView(APIView):
    def __init__(self):
        """
        :param get_response:
        """

        self.config = settings.KEYCLOAK_CONFIG

        # Read configurations
        try:
            self.server_url = self.config['KEYCLOAK_SERVER_URL']
            self.client_id = self.config['KEYCLOAK_CLIENT_ID']
            self.realm = self.config['KEYCLOAK_REALM']
        except KeyError as e:
            raise Exception("KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID or KEYCLOAK_REALM not found.")

        self.client_secret_key = self.config.get('KEYCLOAK_CLIENT_SECRET_KEY', None)
        self.client_public_key = self.config.get('KEYCLOAK_CLIENT_PUBLIC_KEY', None)
        # self.mykeycloakHttpRequest = KeycloakHttpRequest(server_url,client_secret_key,"1234567890",realm,client_id)


    keycloak_scopes = {'GETs': 'read-only-admin-view', 'POSTs': 'edit-admin-view', 'DEFAULTs': 'default-admin-view'}

    def get(self, request):
        refreshToken = request.GET.get('refreshToken', '')
        # print("Debug: the refresh token is: " + refreshToken)
        try:
            mykeycloakHttpRequest = KeycloakHttpRequest(self.server_url,self.client_secret_key, self.realm,self.client_id)
            accessTokenInfo = mykeycloakHttpRequest.get_access_token(refreshToken)
            # print("Debug: the keycloak token info is: " + json.dumps(accessTokenInfo))
            if "status" in accessTokenInfo:
                return Response(data={"detail": accessTokenInfo['detail']},status=accessTokenInfo['status'])
            elif accessTokenInfo:
                return Response(data=accessTokenInfo,status=200)
            else:
                return Response(data={},status=NotAuthenticated.status_code)
        except Exception as e:
            print("Debug: the error message: " + e)
            return Response(data={},status=NotAuthenticated.status_code)

    def post(self, request, format=None):
        print("Debug: the server_url: " + self.server_url)
        print("Debug: the client_secret_key: " + self.client_secret_key)
        print("Debug: the realm: " + self.realm)
        print("Debug: the client_id: " + self.client_id)
        code = request.data['code']
        redirect_uri = request.data['redirect_uri']
        try:
            mykeycloakHttpRequest = KeycloakHttpRequest(self.server_url,self.client_secret_key,self.realm,self.client_id)
            keycloakTokenInfo = mykeycloakHttpRequest.get_refresh_token(code,redirect_uri);
            # print("Debug: the keycloak token info is: " + json.dumps(keycloakTokenInfo))
            if keycloakTokenInfo:
                return Response(data=keycloakTokenInfo,status=200)
            else:
                return Response(data={},status=NotAuthenticated.status_code)
        except Exception as e:
            print("Debug: the error message: " + e)
            return Response(data={},status=NotAuthenticated.status_code)

class KeycloakLogoutView(APIView):
    def __init__(self):
        self.config = settings.KEYCLOAK_CONFIG
        # Read configurations
        try:
            self.server_url = self.config['KEYCLOAK_SERVER_URL']
            self.client_id = self.config['KEYCLOAK_CLIENT_ID']
            self.realm = self.config['KEYCLOAK_REALM']
        except KeyError as e:
            raise Exception("KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID or KEYCLOAK_REALM not found.")

        self.client_secret_key = self.config.get('KEYCLOAK_CLIENT_SECRET_KEY', None)
        self.client_public_key = self.config.get('KEYCLOAK_CLIENT_PUBLIC_KEY', None)
        # self.mykeycloakHttpRequest = KeycloakHttpRequest(server_url,client_secret_key,"1234567890",realm,client_id)

    keycloak_scopes = {'GETs': 'read-only-admin-view', 'POSTs': 'edit-admin-view', 'DEFAULTs': 'default-admin-view'}

    def get(self, request):
        redirect_uri = request.GET.get('redirect_uri', '')
        print("Debug: the redirect_uri is: " + redirect_uri)
        try:
            mykeycloakHttpRequest = KeycloakHttpRequest(self.server_url,self.client_secret_key,self.realm,self.client_id)
            logoutResInfo = mykeycloakHttpRequest.keycloak_logout_get(redirect_uri);
            if logoutResInfo:
                return Response(data=logoutResInfo,status=200)
            else:
                return Response(data={},status=NotAuthenticated.status_code)
        except Exception as e:
            print("Debug: the error message: " + str(e))
            return Response(data={},status=NotAuthenticated.status_code)

    def post(self, request, format=None):
        print("Debug: try to logout")
        userName = request.data['username']
        refreshToken = request.data['refreshToken']
        try:
            mykeycloakHttpRequest = KeycloakHttpRequest(self.server_url,self.client_secret_key,self.realm,self.client_id)
            logoutResInfo = mykeycloakHttpRequest.keycloak_logout(refreshToken);
            if logoutResInfo:
                return Response(data=logoutResInfo,status=200)
            else:
                return Response(data={},status=NotAuthenticated.status_code)
        except Exception as e:
            print("Debug: the error message: " + str(e))
            return Response(data={},status=NotAuthenticated.status_code)

class KeycloakConfigView(APIView):
    def __init__(self):
        self.config = settings.KEYCLOAK_CONFIG
        # Read configurations
        try:
            self.server_url = self.config['KEYCLOAK_SERVER_URL']
            self.client_id = self.config['KEYCLOAK_CLIENT_ID']
            self.realm = self.config['KEYCLOAK_REALM']
        except KeyError as e:
            raise Exception("KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID or KEYCLOAK_REALM not found.")

        self.client_secret_key = self.config.get('KEYCLOAK_CLIENT_SECRET_KEY', None)
        self.client_public_key = self.config.get('KEYCLOAK_CLIENT_PUBLIC_KEY', None)
        # self.mykeycloakHttpRequest = KeycloakHttpRequest(server_url,client_secret_key,"1234567890",realm,client_id)

    def get(self, request):
        print("Debug: try to get keycloak config")
        keycloakEnable = True
        data = {}
        if keycloakEnable:
            data = {
                "KEYCLOAK_ENABLE": True,
                "KEYCLOAK_SERVER_URL":"http://localhost:8082",
                "KEYCLOAK_REALM":"master",
                "KEYCLOAK_CLIENT_ID":"frontend-client",
            }
        else:
            data = {
                "KEYCLOAK_ENABLE": False,
                "KEYCLOAK_SERVER_URL":"http://localhost:8082",
                "KEYCLOAK_REALM":"master",
                "KEYCLOAK_CLIENT_ID":"frontend-client",
            }
        print("Debug: the keycloak response data is: " + str(data))
        return Response(data=data,status=200)

    # @method_decorator(csrf_exempt)
    def post(self, request, format=None):
        return Response(data={},status=NotAuthenticated.status_code)

class AutomationTokenView(APIView):
    def __init__(self):
        #Get the accessToken for backend automation test.
        self.config = settings.KEYCLOAK_CONFIG
        # Read configurations
        try:
            self.server_url = self.config['KEYCLOAK_SERVER_URL']
            self.client_id = self.config['KEYCLOAK_CLIENT_ID']
            self.realm = self.config['KEYCLOAK_REALM']
        except KeyError as e:
            raise Exception("KEYCLOAK_SERVER_URL, KEYCLOAK_CLIENT_ID or KEYCLOAK_REALM not found.")

        self.client_secret_key = self.config.get('KEYCLOAK_CLIENT_SECRET_KEY', None)

    def get(self, request):
        return Response(data={},status=200)

    # @method_decorator(csrf_exempt)
    def post(self, request, format=None):
        username = request.data['username']
        password = request.data['password']
        print("Debug: username = %s and password= %s" % (username, password))
        try:
            mykeycloakHttpRequest = KeycloakHttpRequest(self.server_url,self.client_secret_key,self.realm,self.client_id)
            automationTokenInfo = mykeycloakHttpRequest.get_automation_token(username,password);
            if automationTokenInfo:
                return Response(data=automationTokenInfo,status=200)
            else:
                return Response(data={},status=NotAuthenticated.status_code)
        except Exception as e:
            print("Debug: the error message: " + e)
            return Response(data={},status=NotAuthenticated.status_code)
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Marcos Pereira <marcospereira.mpj@gmail.com>
# Modified by Sairam Krish <haisairam@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import logging
from django.conf import settings
from django.http.response import JsonResponse
from rest_framework.response import Response
from django.utils.deprecation import MiddlewareMixin
#from keycloak import KeycloakOpenID
#from keycloak.exceptions import KeycloakInvalidTokenError,raise_error_from_response, KeycloakGetError
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed, NotAuthenticated
import json
#from keycloak import KeycloakAdmin
from users.KeyclaokHttpRequest import KeycloakHttpRequest
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from users.models import Role
from users.serializers import UserSerializer
from users.serializers import RoleSerializer
import threading
import time
import django
import requests

logger = logging.getLogger(__name__)

class KeycloakMiddleware(MiddlewareMixin):

    def __init__(self, get_response):
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
        self.default_access = self.config.get('KEYCLOAK_DEFAULT_ACCESS', "DENY")
        self.method_validate_token = self.config.get('KEYCLOAK_METHOD_VALIDATE_TOKEN', "INTROSPECT")
        self.keycloak_authorization_config = self.config.get('KEYCLOAK_AUTHORIZATION_CONFIG', None)
        self.keycloak_bearer_authentication_exempts = self.config.get('KEYCLOAK_BEARER_AUTHENTICATION_EXEMPT_PATHS', None)

        # Django
        self.get_response = get_response

        #lock
        self.lock = threading.Lock()

    @property
    def config(self):
        return self._config

    @config.setter
    def config(self, value):
        self._config = value

    @property
    def server_url(self):
        return self._server_url

    @server_url.setter
    def server_url(self, value):
        self._server_url = value

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret_key(self):
        return self._client_secret_key

    @client_secret_key.setter
    def client_secret_key(self, value):
        self._client_secret_key = value

    @property
    def client_public_key(self):
        return self._client_public_key

    @client_public_key.setter
    def client_public_key(self, value):
        self._client_public_key = value

    @property
    def realm(self):
        return self._realm

    @realm.setter
    def realm(self, value):
        self._realm = value

    @property
    def keycloak_authorization_config(self):
        return self._keycloak_authorization_config

    @keycloak_authorization_config.setter
    def keycloak_authorization_config(self, value):
        self._keycloak_authorization_config = value

    @property
    def method_validate_token(self):
        return self._method_validate_token

    @method_validate_token.setter
    def method_validate_token(self, value):
        self._method_validate_token = value

    def __call__(self, request):
        """
        :param request:
        :return:
        """
        print("Debug: try to invoke the view class")
        return self.get_response(request)

    def getRole(self, name):
        #if self.debug_flag :
        #    self.logger.info("Class Login: enter the function getRole(), input parameter[name:" + name + " ]")
        return Role.objects.filter(name=name)

    def process_view(self, request, view_func, view_args, view_kwargs):
        """
        Validate only the token introspect.
        :param request: django request
        :param view_func:
        :param view_args: view args
        :param view_kwargs: view kwargs
        :return:
        """
        #Check if this request path is no authentication required, if yes, go to views.
        if len(self.keycloak_bearer_authentication_exempts) > 0:
        #if hasattr(settings, 'KEYCLOAK_BEARER_AUTHENTICATION_EXEMPT_PATHS'):
            path = request.path_info.lstrip('/')
            print("Debug: the url path is " + path)
            if any(re.match(m, path) for m in
                   self.keycloak_bearer_authentication_exempts):
                logger.debug('** exclude path found, skipping')
                return None
        
        # try:
        #     view_scopes = view_func.cls.keycloak_scopes
        # except AttributeError as e:
        #     logger.debug('Allowing free acesss, since no authorization configuration (keycloak_scopes) found for this request route :%s',request)
        #     return None
        # # Get default if method is not defined.
        # required_scope = view_scopes.get(request.method, None) \
        #     if view_scopes.get(request.method, None) else view_scopes.get('DEFAULT', None)
        # # DEFAULT scope not found and DEFAULT_ACCESS is DENY
        # if not required_scope and self.default_access == 'DENY':
        #     return JsonResponse({"detail": PermissionDenied.default_detail},
        #                         status=PermissionDenied.status_code)
        # print("Debug: the required_scope is " + required_scope)
        accessToken = "";
        if 'HTTP_AUTHORIZATION' not in request.META:
            if not request.META.get('HTTP_COOKIE'):
                print("Debug: can't get the cookie keycloak token");
                return JsonResponse({"detail": NotAuthenticated.default_detail},
                    status=NotAuthenticated.status_code)
            else:
                accessToken =request.COOKIES["keycloakToken"];
                print("Debug: the request cookie token is: " + accessToken);

        if not accessToken.strip():
            auth_header = request.META.get('HTTP_AUTHORIZATION').split()
            accessToken = auth_header[1] if len(auth_header) == 2 else auth_header[0]
            print("Debug: the request token is " + accessToken);

        try:
            # print("Debug: try to get user info")
            keycloakHttpRequest = KeycloakHttpRequest(self.server_url,self.client_secret_key,self.realm,self.client_id)
            keycloakUserInfo = keycloakHttpRequest.get_userinfo(accessToken)
            print("Debug: the keycloakUserInfo is: " + json.dumps(keycloakUserInfo))
            keycloakUserRoles=''
            #print("Debug: the userInfoData username is %s, user ID is %s " % (userinfo['preferred_username'],userinfo['sub']))
            if keycloakUserInfo is not None: 
                if "res_status" in keycloakUserInfo:
                    return JsonResponse({"detail": keycloakUserInfo['detail']},status=keycloakUserInfo['res_status'])
                
                if 'user_roles' in keycloakUserInfo:
                    # print("Debug: enter the user_roles if.")
                    keycloakUserRoles = keycloakUserInfo['user_roles']
                    request.META['USER_ROLES'] = ','.join(keycloakUserRoles)
                    if 'group_info' in keycloakUserInfo and keycloakUserInfo['group_info']:
                        request.META['USER_GROUPS'] = ','.join(keycloakUserInfo['group_info'])
                    else:
                        request.META['USER_GROUPS'] = 'None'
                else:
                    #Get user roles(User must have the Client Roles 'view-users', otherwise there will be exception.)
                    print("Debug: current user is: " + keycloakUserInfo['sub'])
                    roles = keycloakHttpRequest.get_user_roles(keycloakUserInfo['sub'],accessToken)
                    if "res_status" in roles:
                        return JsonResponse({"detail": roles['detail']},status=roles['res_status'])
                    print("Debug: roles info is: ")
                    if roles is None or not len(roles):
                        # print("Debug: keycloak roles is None")
                        keycloakUserRoles = None
                        request.META['USER_ROLES'] = 'CCTF_VIEWER'
                        if 'group_info' in keycloakUserInfo and keycloakUserInfo['group_info']:
                            request.META['USER_GROUPS'] = ','.join(keycloakUserInfo['group_info'])
                        else:
                            request.META['USER_GROUPS'] = 'None'
                    else:
                        # print("Debug: try to analysis user roles.")
                        # print("Debug: the keycloak roles info is " + json.dumps(roles))
                        keycloakUserRoles = [user['name'] for user in roles]
                        request.META['USER_ROLES'] = ','.join(keycloakUserRoles)
                        if 'group_info' in keycloakUserInfo and keycloakUserInfo['group_info']:
                            request.META['USER_GROUPS'] = ','.join(keycloakUserInfo['group_info'])
                        else:
                            request.META['USER_GROUPS'] = 'None'
                        #request.META['USER_NAME'] = keycloakUserInfo['preferred_username']
                        print("Debug: the keycloak roles info is " + json.dumps(keycloakUserRoles))

                #Check if there is one local user with name keycloakUserInfo['preferred_username'] which is the keycloak login username.
                # print("Debug: current user name is " + keycloakUserInfo['preferred_username'])
                # User.objects.create_user(keycloakUserInfo['preferred_username'], 'bwang018@163.com', 'testpass')
                localUser = User.objects.filter(username = str(keycloakUserInfo['preferred_username']))
                password=''
                if len(localUser):
                    #If there is a local user, get this local user's password(This is for CCTF system data migration)
                    password=localUser[0].password
                else:
                    # print("Debug: try to add user locally.")
                    #If there is no local user, create one new local user with the keycloak user info, but set a common password
                    password='commonpassword'
                    email=''
                    if not('email' in keycloakUserInfo):
                        # print("Debug: dict keycloakUserInfo has no key email")
                        email="test@test.com"
                    elif re.match(r'\w+\.?\w*\@.+\.[a-z]+',keycloakUserInfo['email']):
                        email=keycloakUserInfo['email']
                    else:
                        email="test@test.com"
                    time.sleep(2)
                    #????? Does the password need to be encrypted?????????????????????????????????????????????????????????????????????????
                    try:
                        User.objects.create_user(keycloakUserInfo['preferred_username'], email, password)
                    except Exception as e:
                        print("Execption: " + str(e))
                        if not '1062' in str(e) and not 'Duplicate entry' in str(e):
                            return JsonResponse({"detail": str(e)},status=500)


                #Resolve the user role when changes the user role info on the keycloak GUI.
                parameter = {
                    'name':'',
                    'role':'',
                    'changeFlag':False
                }
                if keycloakUserRoles is not None:
                    if 'CCTF_ADMIN' in keycloakUserRoles:
                        parameter['role'] = '1'
                    elif 'CCTF_OPERATOR' in keycloakUserRoles:
                        parameter['role'] = '2'
                    else:
                        parameter['role'] = '3'
                else:
                    parameter['role'] = '3'
                parameter['name'] = keycloakUserInfo['preferred_username']
                roleQueryset = self.getRole(parameter['name'])
                if len(roleQueryset) > 0 :
                    serializer = RoleSerializer(roleQueryset, many=True)
                    if serializer.data[0]['role'] != parameter['role'] :
                        print("Debug: try to change user role.")
                        updateSerializer = RoleSerializer(roleQueryset.first(), data=parameter, partial=True)
                        if updateSerializer.is_valid():
                            updateSerializer.save() # Update the local user's role info.
                else :
                    #Add local role info for the local user.
                    saveSerializer = RoleSerializer(data=parameter)
                    if saveSerializer.is_valid():
                        try:
                            saveSerializer.save()
                        except Exception as e:
                            if not '1062' in str(e) and not 'Duplicate entry' in str(e):
                                return JsonResponse({"detail": str(e)},status=500)

                #addOperationLog('login',request, self.ar.resBody())

                #Add the user info to http request.
                if str(request.user) == 'AnonymousUser':
                    localuser = User.objects.get(username = str(keycloakUserInfo['preferred_username']))
                    request.user = localuser
                    print("Debug: the current user info is " + str(localuser))
                    #request.user.is_authenticated = True
                    # print('Debug: try to login')
                    # user = authenticate(request, username=keycloakUserInfo['preferred_username'], password=password)
                    # if user is not None:
                    #     login(request, user)

                return None

        except Exception as e:
            print("Debug: print the execption info: " + str(e))
            print("Debug: print type of the execption info: " + str(type(e)))
            print("\n\n") 
            if type(e) == requests.exceptions.ConnectionError :
                return JsonResponse({"detail": "ConnectionError, can't connect the keycloak server."},status=500)
            elif type(e) == django.db.utils.OperationalError:
                return JsonResponse({"detail": str(e)},status=500)
            return JsonResponse(data={"detail": AuthenticationFailed.default_detail},status=AuthenticationFailed.status_code)

        # User Permission Denied
        # return JsonResponse({"detail": PermissionDenied.default_detail},
        #                     status=PermissionDenied.status_code)

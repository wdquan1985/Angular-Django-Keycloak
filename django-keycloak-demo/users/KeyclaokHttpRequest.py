# -*- coding: utf-8 -*-
import requests
import json
import sys

class KeycloakHttpRequest(object):
    def __init__(self,server_url,client_secret_key,realm='master',client_id='admin-cli'):
        if server_url.endswith('/'):
            self.server_url = server_url[:-1]
        else:
            self.server_url = server_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret_key = client_secret_key
        self.proxies={
            'http':'http://cnproxy.int.nokia-sbell.com/proxy.pac',
            'https':'http://cnproxy.int.nokia-sbell.com/proxy.pac'
        }

    def get_userinfo(self, accessToken):
        headers={
            'Authorization': 'Bearer ' + accessToken,
            'Content-Type': 'application/json'
        }
        #http://$KC_SERVER/$KC_CONTEXT/realms/$KC_REALM/protocol/openid-connect/userinfo"
        userInfoUrl = '%s/realms/%s/protocol/openid-connect/userinfo' % (self.server_url,self.realm)
        try:
            #userInfoResponse = requests.get(url = userInfoUrl, headers=self.headers,verify=False,proxies=self.proxies)
            userInfoResponse = requests.get(url = userInfoUrl, headers=headers,verify=False)
            userInfoData=''
            print("debug: the userinfo reponse info is : " + str(userInfoResponse))
            if userInfoResponse.headers.get('Content-Type') is not None and 'json' in userInfoResponse.headers.get('Content-Type'):
                userInfoData = userInfoResponse.json()
            else:
                if userInfoResponse.status_code == 403:
                    userInfoData = {"res_status":403,"detail":"This user does not have permission to access the user info from keycloak."}
                elif userInfoResponse.status_code == 401:
                    userInfoData = {"res_status":401,"detail": str(userInfoResponse)}
                else:
                    userInfoData = {"res_status":userInfoResponse.status_code,"detail":"Can't get the user info from keycloak server."}
            return userInfoData
        except Exception as e:
            print("Debug: the error message: " + str(e))
            print("Debug: the type of Exception : " + str(type(e)))
            if type(e) == requests.exceptions.ConnectionError :
                return {"res_status":500,"detail":"ConnectionError, can't connect the keycloak server."}
            return {"res_status":401,"detail":"Can't get the user info from keycloak server."}

    def get_user_roles(self,user_uuid, accessToken):
        headers={
            'Authorization': 'Bearer ' + accessToken,
            'Content-Type': 'application/json'
        }
        #/auth/admin/realms/{realm}/users/{user-uuid}/role-mappings/realm
        URL = '%s/admin/realms/%s/users/%s/role-mappings/realm' % (self.server_url,self.realm,user_uuid)
        # sending get request and saving the response as response object 
        try:
            # print("Debug: try to get user roles from keycloak server " + URL)
            #reponse = requests.get(url = URL, headers=self.headers,verify=False,proxies=self.proxies)
            response = requests.get(url = URL, headers=headers,verify=False)
            print("Debug: user roles reponse string is:" + str(response.headers))
            print("Debug: user roles reponse string is:" + str(response.headers.get('Content-Type')))
            userRoleData=''
            if response.headers.get('Content-Type') is not None and 'json' in response.headers.get('Content-Type'):
                # extracting data in json format 
                # print("Debug: user roles reponse string is:" + str(response))
                data = response.json()
                # print("Debug: the user roles info is " + str(data))
                return data
            else:
                if response.status_code == 403:
                    userRoleData = {"res_status":403,"detail":"This user does not have permission to get the user role info from keycloak."}
                elif response.status_code == 401:
                    userRoleData = {"res_status":401,"detail": str(response)}
                else:
                    userRoleData = {"res_status":response.status_code,"detail":"Can't get the user role info from keycloak server."}
                return userRoleData
        except Exception as e:
            print("Debug: the error message: " + str(e))
            print("Debug: the type of Exception : " + str(type(e)))
            if type(e) == requests.exceptions.ConnectionError :
                return {"res_status":500,"detail":"ConnectionError, can't connect the keycloak server."}
            return {"res_status":500,"detail":"Can't get the user role info from keycloak server."}

    def get_refresh_token(self, code, redirect_uri):
        payload = {
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": 'authorization_code',
            "client_secret": self.client_secret_key
        }
        #/auth/admin/realms/{realm}/users/{user-uuid}/role-mappings/realm
        URL = '%s/realms/%s/protocol/openid-connect/token' % (self.server_url,self.realm)
        # sending get request and saving the response as response object 
        try:
            #reponse = requests.get(url = URL, headers=self.headers,verify=False,proxies=self.proxies)
            response = requests.post(url = URL, data=payload,verify=False)
            refreshToken = ""
            if response.headers.get('Content-Type') is not None and 'json' in response.headers.get('Content-Type'):
                # extracting data in json format 
                data = response.json()
                # print("Debug: the access_token info is: " + str(data))
                return data
            else:
                if response.status_code == 403:
                    refreshToken = {"res_status":403,"detail":"This user does not have permission to get the refresh token from keycloak."}
                elif response.status_code == 401:
                    refreshToken = {"res_status":401,"detail": str(response)}
                else:
                    refreshToken = {"res_status":response.status_code,"detail":"Can't get the the refresh token from keycloak server."}
                return refreshToken
        except Exception as e:
            print("Debug: the error message: " + str(e))
            if type(e) == requests.exceptions.ConnectionError :
                return {"res_status":500,"detail":"ConnectionError, can't connect the keycloak server."}
            return {"res_status":500,"detail":"Can't get the refresh token from keycloak server."}

    def get_access_token(self, refreshToken): 
        #Refresh the access_token using the refresh_token
        payload = {
            "client_id": self.client_id,
            "grant_type": 'refresh_token',
            "refresh_token": refreshToken,
            "client_secret": self.client_secret_key
        }
        #/auth/admin/realms/{realm}/users/{user-uuid}/role-mappings/realm
        URL = '%s/realms/%s/protocol/openid-connect/token' % (self.server_url,self.realm)
        # sending get request and saving the response as response object 
        try:
            #reponse = requests.get(url = URL, headers=self.headers,verify=False,proxies=self.proxies)
            response = requests.post(url = URL, data=payload,verify=False)
            if response.headers.get('Content-Type') is not None and 'json' in response.headers.get('Content-Type'):
                # extracting data in json format 
                data = response.json()
                # print("Debug: the access_token info is: " + str(data))
                return data
            else:
                if response.status_code == 403:
                    refreshToken = {"res_status":403,"detail":"This user does not have permission to get the access token from keycloak."}
                elif response.status_code == 401:
                    refreshToken = {"res_status":401,"detail": str(response)}
                else:
                    refreshToken = {"res_status":response.status_code,"detail":"Can't get the the access token from keycloak server."}
                return refreshToken
        except Exception as e:
            print("Debug: the error message: " + str(e))
            if type(e) == requests.exceptions.ConnectionError :
                return {"res_status":500,"detail":"ConnectionError, can't connect the keycloak server."}
            return {"res_status":500,"detail":"Can't get the access token from keycloak server."}

    def get_automation_token(self, username, password): 
        #Get the accessToken for backend automation test.
        payload = {
            "client_id": self.client_id,
            "grant_type": 'password',
            "client_secret": self.client_secret_key,
            "scope": 'openid',
            "username": username,
            "password": password
        }
        #/auth/admin/realms/{realm}/users/{user-uuid}/role-mappings/realm
        URL = '%s/realms/%s/protocol/openid-connect/token' % (self.server_url,self.realm)
        # sending get request and saving the response as response object 
        try:
            #reponse = requests.get(url = URL, headers=self.headers,verify=False,proxies=self.proxies)
            print("Debug: try to get access token for automation")
            response = requests.post(url = URL, data=payload,verify=False)
            if response.headers.get('Content-Type') is not None and 'json' in response.headers.get('Content-Type'):
                # extracting data in json format 
                data = response.json()
                # print("Debug: the access_token info is: " + str(data))
                return data
            else:
                return None
        except Exception as e:
            print("Debug: the error message: " + str(e))
            return None

    def keycloak_logout(self, refreshToken): 
        #Refresh the access_token using the refresh_token
        payload = {
            "client_id": self.client_id,
            "refresh_token": refreshToken,
            "client_secret": self.client_secret_key
        }
        #/auth/admin/realms/{realm}/users/{user-uuid}/role-mappings/realm
        URL = '%s/realms/%s/protocol/openid-connect/logout' % (self.server_url,self.realm)
        # sending get request and saving the response as response object 
        try:
            #reponse = requests.get(url = URL, headers=self.headers,verify=False,proxies=self.proxies)
            print("Debug: try to logout this login")
            reponse = requests.post(url = URL, data=payload,verify=False)
            return {"detail": "Login successfully."}
        except Exception as e:
            print("Debug: the error message: " + str(e))
            return None

    def keycloak_logout_get(self, redirect_uri):
        URL = '%s/realms/%s/protocol/openid-connect/logout?redirect_uri=%s' % (self.server_url,self.realm,redirect_uri)
        # sending get request and saving the response as response object
        try:
            #reponse = requests.get(url = URL, headers=self.headers,verify=False,proxies=self.proxies)
            response = requests.get(url = URL, verify=False)
            if response.headers.get('Content-Type') is not None and 'json' in response.headers.get('Content-Type'):
                # extracting data in json format 
                data = response.json()
                # print("Debug: the access_token info is: " + str(data))
                return data
            else:
                if response.status_code == 403:
                    refreshToken = {"res_status":403,"detail":"This user does not have permission to get the access token from keycloak."}
                elif response.status_code == 401:
                    refreshToken = {"res_status":401,"detail": str(response)}
                else:
                    refreshToken = {"res_status":response.status_code,"detail":"Can't get the the access token from keycloak server."}
                return refreshToken
        except Exception as e:
            print("Debug: Can't logout from keycloak because of: " + str(e))
            self.logger.error("Exception found when try to logout from keycloak: " + str(e))
            return None

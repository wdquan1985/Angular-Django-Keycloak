import { KeycloakService } from 'keycloak-angular';

export function initializeKeycloak(keycloak: KeycloakService) {
  // return  () =>
  //   this.keycloakServicePer.init({
  //       realm: "master",
  //       url: 'http://localhost:8082/auth',
  //       clientId: 'frontend-client',
  //       credentials : "5d984e0b-6da3-452d-b951-44d642881ce8"
  //   }).then( (authenticated) => {
  //       console.log("Debug: the user name is " + this.keycloakServicePer.getUsername());
  //       console.log("Debug: the access token is " + this.keycloakServicePer.getToken());
  //       console.log("Debug: the user roles is " + this.keycloakServicePer.getUserRoles());
  //       //loadData();
  //       alert(authenticated ? 'authenticated' : 'not authenticated');
  //   }).catch(function(e) {
  //       console.log("Debug: the error info is: " + e)
  //       alert('failed to initialize');
  //   });

  return () =>
    keycloak.init({
        config: {
            realm: "master",
            url: 'https://127.0.0.1:8443/auth',
            clientId: 'cctf-frontend-client',
            credentials : {secret : "8f28abe0-f4de-476d-bd8b-5354d78639de"}
        },
        initOptions: {
            onLoad: 'login-required',
            flow: 'standard'
        },
    }).then(() => {
        var roleId = "0";
        var roleTypes = {"ROLE_ADMIN": "1","ROLE_VIEWER": "2", "ROLE_OPERATOR": "3"};
        var roleArray = keycloak.getUserRoles(true);
        if(roleArray.length == 0){
          roleId = '3';
        }else{
          console.log("Debug: the current user roles is " + roleArray);
          for(var key in roleTypes){
            if(roleArray.indexOf(key) > -1){
              roleId = roleTypes[key];
              break;
            }else{
              roleId = '3';
            }
          }
        }
        
        sessionStorage.setItem('refreshToken', "");
        console.log("Debug: the current user name is: " + keycloak.getUsername(),)
        keycloak.getToken().then(data => {
          console.log("Debug: the keycloak token is " + data);
        })
    }).catch((error) =>
        console.error('Keycloak login failed: ', error)
    );

}
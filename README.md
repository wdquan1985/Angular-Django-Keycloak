# Angular-Django-Keycloak  
## Install Keycloak 
Download keycloak zip file from https://www.keycloak.org/downloads.  
Unzip keycloak-6.0.1.zip on windows, double click the bin\standalone.bat to start the keycloak server.
Keycloak server is running on https://127.0.0.1:8843/auth now, user can edit standalone\configuration\standalone.xml to change port.  

## Front End  
**1.Install dependencis for angular application**  
yarn install  
**2.Running angular application**  
yarn start  
Open http://localhost:4200/ on browser.

## Back End  
**1.Create python virtual env**  
pip install virtualenv  
virtualenv keycloakTestEnv  
**2.Activate the python virtual env**  
.\keycloakTestEnv\Scripts\activate.bat  
**3.Install python dependencies for application**  
pip install -r requirements.txt  
**4.Run the application**  
python manage.py runserver 8088

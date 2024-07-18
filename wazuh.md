# Wazuh SSO with Microsoft Entra ID 
## There are three stages in the single sign-on integration. 
- Microsoft Entra ID Configuration
- Wazuh indexer configuration
- Wazuh dashboard configuration

## Microsoft Entra ID Configuration 
1. Go to Microsoft Azure Portal > Microsoft Entra ID > Enterprise applications > New application and create your own application.

    ![image](https://github.com/user-attachments/assets/457640a8-141d-4ecf-aaa5-3312dd30ec9e)
2. Select ‘Integrate any other application you don't find in the gallery’, give name to your application and click Add.
3. Create a role for your application for that go to Microsoft Entra ID and click on App registrations. Select your new app under All applications and click Manifest.
4. Add a new role to your application's Manifest:
    
```bash
{ 
   "allowedMemberTypes": [ 
      "User" 
   ], 
   "description": "Wazuh role", 
   "displayName": "Wazuh_role", 
   "id": "<application_id>", 
   "isEnabled": true, 
   "lang": null, 
   "origin": "Application", 
   "value": "Wazuh_role" 
},
```
Replace <application_id> with your actual value.

![image](https://github.com/user-attachments/assets/93f1e4b8-5982-4408-a208-62a703086731)

5. Save the changes and proceed to the next step. 

![image](https://github.com/user-attachments/assets/828756cf-1a47-425d-9f31-b4a8c646c04f)

6. Assign a user to the app for that go to Microsoft Entra ID > Enterprise applications > select your application > Assign users and groups (or Users and Groups in the panel to the left).
7. Click on Add user/group, assign a user and select the role we created in Manifest.

   ![image](https://github.com/user-attachments/assets/4033d85e-02e6-4bdc-9d9a-78f76f822f62)
8. To Configure Single sign-on go to Enterprise applications, select your application and then click on Set up single sign-on SAML.
   ![image](https://github.com/user-attachments/assets/00c3899f-4083-48c4-a78b-6d61dd31ac2f)
   ![image](https://github.com/user-attachments/assets/c7167773-e668-41bc-a062-e98b542f7b84)
9. Now there are total 5 options are available to configure sso with use of SAML
    - In option 1, under Basic SAML Configuration, click edit and set wazuh-saml as Identifier (Entity ID)  and https://<WAZUH_DASHBOARD_URL>/_opendistro/_security/saml/acs as Reply URL (Assertion Consumer Service URL), and Replace <WAZUH_DASHBOARD_URL> with the corresponding value. Save and proceed to the next step. 
      ![image](https://github.com/user-attachments/assets/7805f579-ca94-488b-9d02-24654c0e1210)

    -In option 2 under Attributes and Claims go to Edit > click on Add new Claim now select Roles in the name field and user.assignedroles in the Source attribute field. save and continue for next step
      ![image](https://github.com/user-attachments/assets/ba9029cc-8dc8-4c51-9aa7-0becf282ba53)
## Note:- Now in some further steps we have to note down some parameters that will be used in the Wazuh indexer configuration. 
    - In option 3 SAML Certificate, the App Federation Metadata Url will be the idp.metadata_url in the Wazuh indexer configuration file. So, note it down somewhere. Go to the metadata URL using your web browser. Copy the value of the <X509Certificate> field. It’s your exchange_key parameter. 
      ![image](https://github.com/user-attachments/assets/479ed7e7-5948-4817-aa06-5b9bc7f95e6b)
    - In option 4, the Microsoft Entra ID Identifier will be our idp.entity_id in wazuh so note it down also. 
# Wazuh indexer configuration 
### Edit the /etc/wazuh-indexer/opensearch-security/config.yml file and change the following values: 

- Set the order in basic_internal_auth_domain to 0 and the challenge flag to false. 
- Include a saml_auth_domain configuration under the authc section similar to the following:
  ``` bash
  authc: 
      basic_internal_auth_domain: 
        description: "Authenticate via HTTP Basic against internal users database" 
        http_enabled: true 
        transport_enabled: true 
        order: 0 
        http_authenticator: 
          type: "basic" 
          challenge: false 
        authentication_backend: 
          type: "intern" 
      saml_auth_domain: 
        http_enabled: true 
        transport_enabled: false 
        order: 1 
        http_authenticator: 
          type: saml 
          challenge: true 
          config: 
            idp: 
              metadata_url: https://login.microsoftonline.com/... 
              entity_id: https://sts.windows.net/... 
            sp: 
              entity_id: wazuh-saml 
            kibana_url: https://<WAZUH_DASHBOARD_URL> 
            roles_key: Roles 
            exchange_key: 'MIIC8DCCAdigAwIBAgIQXzg.........' 
        authentication_backend: 
          type: noop
  ```
  - Ensure to change the highlighted parameters to their corresponding values. 
### Run the securityadmin script to load the configuration changes made in the config.yml file. 
``` bash
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/config.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h localhost -nhnv 

```
The -h flag specifies the hostname or the IP address of the Wazuh indexer node. Note that this command uses localhost, set your Wazuh indexer address if necessary. 
 

The command output must be similar to the following 

OUTPUT: 
``` bash
Security Admin v7 
Will connect to localhost:9200 ... done 
Connected as "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US" 
OpenSearch Version: 2.8.0 
Contacting opensearch cluster 'opensearch' and wait for YELLOW clusterstate ... 
Clustername: wazuh-cluster 
Clusterstate: GREEN 
Number of nodes: 1
Number of data nodes: 1 
.opendistro_security index already exists, so we do not need to create one. 
Populate config from /etc/wazuh-indexer/opensearch-security 
Will update '/config' with /etc/wazuh-indexer/opensearch-security/config.yml 
   SUCC: Configuration for 'config' created or updated 
SUCC: Expected 1 config types for node {"updated_config_types":["config"],"updated_config_size":1,"message":null} is 1 (["config"]) due to: null 
Done with success
```
### Edit the /etc/wazuh-indexer/opensearch-security/roles_mapping.yml file and add the Wazuh_role as shown below: 
``` bash
all_access: 
  reserved: false 
  hidden: false 
  backend_roles: 
  - "admin" 
  - "Wazuh_role" 
  description: "Maps admin to all_access"
```
### Run the securityadmin script to load the configuration changes made in the roles_mapping.yml file. 
``` bash
export JAVA_HOME=/usr/share/wazuh-indexer/jdk/ && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -f /etc/wazuh-indexer/opensearch-security/roles_mapping.yml -icl -key /etc/wazuh-indexer/certs/admin-key.pem -cert /etc/wazuh-indexer/certs/admin.pem -cacert /etc/wazuh-indexer/certs/root-ca.pem -h localhost -nhnv
```
The -h flag specifies the hostname or the IP address of the Wazuh indexer node. Note that this command uses localhost, set your Wazuh indexer address if necessary. 

The command output must be similar to the following 

OUTPUT: 
``` bash
Security Admin v7 
Will connect to localhost:9200 ... done 
Connected as "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US" 
OpenSearch Version: 2.8.0 
Contacting opensearch cluster 'opensearch' and wait for YELLOW clusterstate ... 
Clustername: wazuh-cluster 
Clusterstate: GREEN 
Number of nodes: 1 
Number of data nodes: 1 
.opendistro_security index already exists, so we do not need to create one. 
Populate config from /etc/wazuh-indexer/opensearch-security 
Will update '/rolesmapping' with /etc/wazuh-indexer/opensearch-security/roles_mapping.yml 
   SUCC: Configuration for 'rolesmapping' created or updated 
SUCC: Expected 1 config types for node {"updated_config_types":["rolesmapping"],"updated_config_size":1,"message":null} is 1 (["rolesmapping"]) due to: null 
Done with success
```
# Wazuh dashboard configuration 
### Go to /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml and check the of run_as if it is set to false then go for next step. 
``` bash
hosts: 
  - default: 
      url: https://localhost 
      port: 55000 
      username: wazuh-wui 
      password: "<wazuh-wui-password>" 
      run_as: false
```
### If run_as is set to true, you need to add a role mapping on the Wazuh dashboard. To map the backend role to Wazuh, follow these steps: 

1. GO to wazuh dashboard and select Security, and then Roles mapping to open the page.
  ![image](https://github.com/user-attachments/assets/58b5a272-9b77-44ad-a804-9ff421868721)
2. Click Create Role mapping and complete the empty fields with the following parameters:
-  Role mapping name: Assign a name to the role mapping. 

Roles: Select administrator. 

Custom rules: Click Add new rule to expand this field. 

User field: backend_roles. 

Search operation: FIND. 

Value: Assign the backend role from the Microsoft Entra ID configuration, in our case, this is Wazuh_role. 
![image](https://github.com/user-attachments/assets/ec24beb3-3e01-4cfb-b582-ceae69252d6d)

3. Click save role mapping to save and map the backend role with Wazuh as administrator. 
### Edit this file /etc/wazuh-dashboard/opensearch_dashboards.yml and add the following in it: 
``` bash
opensearch_security.auth.type: "saml" 
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout", "/_opendistro/_security/saml/acs/idpinitiated"] 
opensearch_security.session.keepalive: false
```
### Restart the wazuh-dashboard service with following command: 
``` bash
systemctl restart wazuh-dashboard
```

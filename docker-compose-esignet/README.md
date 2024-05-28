This is the docker-compose setup to run esignet UI and esignet-service with mock identity system.

1. "app" folder holds the Dockerfile required to build custom artifactory-server. This artifactory server will host all the files under app/static folder.
2. "config" folder holds the esignet and mock-identity system properties file.
3. "docker-compose.yml" file with esignet and mock-identity-system setup with other required services
4. "init.sql" comprises DDL and DMLs required by esignet and mock-identity-system.
5. "loader_path" this is esignet mount volume from where all the runtime dependencies are loaded to classpath.


How to run this setup?

1. Start the docker-compose file

> docker-compose up

2. Create OIDC client

http://localhost:8088/v1/esignet/swagger-ui/index.html#/client-management-controller/createOAuthClient


3. Create a mock identity

http://localhost:8082/v1/mock-identity-system/swagger-ui/index.html#/identity-controller/createIdentity

Note: Postman collection is also available [here](https://github.com/mosip/esignet/blob/master/docs/postman-collections/esignet-OIDC-flow-with-mock.postman_collection.json)

4. Invoke the authorize endpoint of esignet UI to start OIDC flow

http://localhost:3000/authorize?nonce=ere973eieljznge2311&state=eree2311&client_id=test-client&redirect_uri=https://healthservices-esignet.collab.mosip.net/userprofile&scope=openid&response_type=code&acr_values=mosip:idp:acr:generated-code&claims=%7B%22userinfo%22:%7B%22name%22:%7B%22essential%22:false%7D,%22phone_number%22:%7B%22essential%22:true%7D%7D,%22id_token%22:%7B%7D%7D&claims_locales=en&display=page&state=consent&ui_locales=en-IN

Note: Change the value of client_id, redirect_uri, acr_values and claims as per your requirement in the above URL.


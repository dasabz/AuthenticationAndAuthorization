### Authorization and Authentication Service

##### The service allows users to be authenticated, and authorizes different behavior

##### The system is designed as a distributed system where

##### 1. AuthenticationManagerFacade is a manager via which the system can be accessed, and it uses 4 services (AuthenticationService, RoleService, UserService and SaltService)
##### 2. UserService is responsible for adding a user , deleting a user to the system as well as authenticating a particular user. UserService uses the AuthenticationService and SaltService in conjunction in order to authenticate a user
##### 3. RoleService is responsible for adding/deleting roles in the system as well as associating roles with existing users. RoleService uses the AuthenticationService for authentication
##### 4. SaltService provides the salted password to ensure robustness to ensure the password is encrypted and stored securely
##### 5. AuthenticationService provides the authenticationToken used across the system

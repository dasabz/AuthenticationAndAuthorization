### Authorization and Authentication Service

##### The service allows users to be authenticated, and authorizes different behavior

##### The system is designed as a distributed system where

##### 1. AuthenticationManagerFacade is a manager via which the system can be accessed, and it uses 4 services (AuthenticationService, RoleService, UserService and SaltService)
##### 2. UserService is responsible for adding a user , deleting a user to the system as well as authenticating a particular user. UserService uses the AuthenticationService and SaltService in conjunction in order to authenticate a user
##### 3. RoleService is responsible for adding/deleting roles in the system as well as associating roles with existing users. RoleService uses the AuthenticationService for authentication
##### 4. SaltService provides the salted password to ensure robustness to ensure the password is encrypted and stored securely
##### 5. AuthenticationService provides the authenticationToken used across the system


##### The main advantage of this design are below:

##### UserService can be enhanced in future for adding more functions like registering with a GroupService to have multiple users in a group 
##### RoleService can be enhanced in future for having roles at a group level as well as individual user level without changing the system too much
##### SaltService can be enhanced in future for adding a different mechanism for adding salt as well as different way of authentication which is more secure
##### AuthenticationService can be enhanced in future as well for having pre-expired tokens at user and group level and maybe not to have pre-expired tokens for some admin cases
##### AuthenticationFacade being just a manager can be continued to be enhanced as and when more and more microservices keep getting added to the system.

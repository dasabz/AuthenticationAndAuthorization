package utils;

public enum AuthenticationStatus {
    Success,
    Failure_User_Already_Exists,
    Failure_User_Does_Not_Exist,
    Failure_Role_Already_Exists,
    Failure_User_Not_Allowed_To_Create_Admin_Role,
    Failure_Role_Does_Not_Exist,
    Failure_User_Not_Allowed_To_Delete_Admin_Role,
    Failure_Cannot_Attach_Admin_Role_To_User

}

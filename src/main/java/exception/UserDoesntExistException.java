package exception;

public class UserDoesntExistException extends Exception{
    public UserDoesntExistException(String s) {
        super(s);
    }

}

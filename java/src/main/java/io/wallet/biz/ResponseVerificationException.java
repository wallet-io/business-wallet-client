package io.wallet.biz;

public class ResponseVerificationException extends Exception {

    private static final long serialVersionUID = 1L;

    public ResponseVerificationException(String message) {
        super(message);
    }

}
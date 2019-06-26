package com.hmtmcse.caa;

public class CryptoAuthException extends Exception {

    public CryptoAuthException(){
        super("Crypto Auth Exception");
    }

    public CryptoAuthException(String message){
        super(message);
    }
}

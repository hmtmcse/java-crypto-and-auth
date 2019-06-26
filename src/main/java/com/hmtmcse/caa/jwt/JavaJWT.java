package com.hmtmcse.caa.jwt;

public class JavaJWT {

    public static enum ALGORITHM {HMAC256, HMAC384, HMAC512, RSA256, RSA384, RSA512, ECDSA256, ECDSA384, ECDSA512}

    public String publicKey = null;
    public String privateKey = null;
    public String secret = null;
    public ALGORITHM algorithm = null;


    public static JavaJWT hmackInstance(ALGORITHM algorithm, String secret){
        JavaJWT javaJWT = new JavaJWT();
        return javaJWT;
    }

    public static JavaJWT rsaInstance(ALGORITHM algorithm, String publicKey, String privateKey){
        JavaJWT javaJWT = new JavaJWT();
        return javaJWT;
    }

    public static JavaJWT ecdsaInstance(ALGORITHM algorithm){
        JavaJWT javaJWT = new JavaJWT();
        return javaJWT;
    }
}

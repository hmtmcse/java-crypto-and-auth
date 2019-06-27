package com.hmtmcse.caa.jwt;

import com.hmtmcse.caa.CryptoAuthException;

public class JavaJWTMain {

    public static void main(String[] args) {
        try {
            JavaJWT javaJWT = JavaJWT.hmackInstance(JavaJWT.ALGORITHM.HMAC256, args[0]);
            System.out.println(javaJWT.tokenValidate(args[1]).getExpiresAt());
        } catch (CryptoAuthException e) {
            System.out.println(e.getMessage());
        }
    }
}

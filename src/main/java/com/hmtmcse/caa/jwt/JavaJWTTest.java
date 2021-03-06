package com.hmtmcse.caa.jwt;

import com.hmtmcse.caa.CryptoAuthException;

public class JavaJWTTest {


    public static void main(String[] args) {
        try {
            JavaJWT javaJWT = JavaJWT.hmackInstance(JavaJWT.ALGORITHM.HMAC256, "miavai").tokenValidUntilUTCMinutes(1);
            String token = javaJWT.token("Test Issuer");
            System.out.println(token);
            System.out.println(javaJWT.tokenValidate(token).getExpiresAt());
        } catch (CryptoAuthException e) {
            e.printStackTrace();
        }
    }

}

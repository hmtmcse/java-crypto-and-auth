package com.hmtmcse.caa.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.hmtmcse.caa.CryptoAuthException;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JavaJWT {

    public static enum ALGORITHM {HMAC256, HMAC384, HMAC512, RSA256, RSA384, RSA512, ECDSA256, ECDSA384, ECDSA512}

    public String publicKey = null;
    public String privateKey = null;
    public String secret = null;
    public ALGORITHM algorithm = null;

    public JavaJWT() throws CryptoAuthException{}

    private Algorithm getHMACAlgo() throws CryptoAuthException {
        if (algorithm == null || secret == null){
            throw new CryptoAuthException("Algorithm or Secret Key Should not be Null");
        }
        if (algorithm.equals(ALGORITHM.HMAC256)){
            return Algorithm.HMAC256(secret);
        }else if (algorithm.equals(ALGORITHM.HMAC384)){
            return Algorithm.HMAC384(secret);
        }else if (algorithm.equals(ALGORITHM.HMAC512)){
            return Algorithm.HMAC512(secret);
        }
        throw new CryptoAuthException("Invalid Algorithm Selected");
    }

    private Algorithm getRSAAlgo() throws CryptoAuthException {
        if (algorithm == null || publicKey == null || privateKey == null) {
            throw new CryptoAuthException("Algorithm or public or private Key Should not be Null");
        }

        RSAPublicKey publicKey = null;
        RSAPrivateKey privateKey = null;

        if (algorithm.equals(ALGORITHM.RSA256)) {
            return Algorithm.RSA512(publicKey, privateKey);
        } else if (algorithm.equals(ALGORITHM.RSA384)) {
            return Algorithm.HMAC384(secret);
        } else if (algorithm.equals(ALGORITHM.RSA512)) {
            return Algorithm.HMAC512(secret);
        }
        throw new CryptoAuthException("Invalid Algorithm Selected");
    }

    public static JavaJWT hmackInstance(ALGORITHM algorithm, String secret) throws CryptoAuthException {
        JavaJWT javaJWT = new JavaJWT();
        return javaJWT;
    }

    public static JavaJWT rsaInstance(ALGORITHM algorithm, String publicKey, String privateKey) throws CryptoAuthException {
        JavaJWT javaJWT = new JavaJWT();
        return javaJWT;
    }

    public static JavaJWT ecdsaInstance(ALGORITHM algorithm) throws CryptoAuthException {
        JavaJWT javaJWT = new JavaJWT();
        return javaJWT;
    }
}

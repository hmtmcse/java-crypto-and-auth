package com.hmtmcse.caa.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.hmtmcse.caa.CryptoAuthException;
import com.hmtmcse.datetimeutil.j7.TMDateHelper;

import java.util.Date;


public class JavaJWT {

    public static enum ALGORITHM {HMAC256, HMAC384, HMAC512, RSA256, RSA384, RSA512, ECDSA256, ECDSA384, ECDSA512}

    public static final String ISSUED_AT = "iat";
    public static final String EXPIRE_AT = "exp";
    public static final String NOT_BEFORE = "nbf";

    private String publicKey = null;
    private String privateKey = null;
    private String secret = null;
    private ALGORITHM algorithm = null;
    private JWTCreator.Builder tokenBuilder = null;


    public JavaJWT() throws CryptoAuthException {
        tokenBuilder = JWT.create();
    }


    private Algorithm getHMACAlgo() throws CryptoAuthException {
        if (algorithm == null || secret == null) {
            throw new CryptoAuthException("Algorithm or Secret Key Should not be Null");
        }
        if (algorithm.equals(ALGORITHM.HMAC256)) {
            return Algorithm.HMAC256(secret);
        } else if (algorithm.equals(ALGORITHM.HMAC384)) {
            return Algorithm.HMAC384(secret);
        } else if (algorithm.equals(ALGORITHM.HMAC512)) {
            return Algorithm.HMAC512(secret);
        }
        throw new CryptoAuthException("Invalid Algorithm Selected");
    }


    public JavaJWT privateClaims(String name, Object value) throws CryptoAuthException {
        if (name == null || value == null) {
            throw new CryptoAuthException("Name or Value Should not be Null");
        }
        if (value instanceof String) {
            tokenBuilder.withClaim(name, value.toString());
        } else if (value instanceof Integer) {
            tokenBuilder.withClaim(name, Integer.parseInt(value.toString()));
        } else if (value instanceof Long) {
            tokenBuilder.withClaim(name, Long.parseLong(value.toString()));
        } else if (value instanceof Double) {
            tokenBuilder.withClaim(name, Double.parseDouble(value.toString()));
        } else if (value instanceof Boolean) {
            tokenBuilder.withClaim(name, Boolean.parseBoolean(value.toString()));
        } else if (value instanceof Date) {
            tokenBuilder.withClaim(name, (Date) value);
        } else {
            throw new CryptoAuthException("Invalid Data Type in Value");
        }
        return this;
    }


    public String token(String issuer) throws CryptoAuthException {
        try {
            tokenBuilder.withIssuer(issuer);
            return tokenBuilder.sign(getHMACAlgo());
        } catch (JWTCreationException exception) {
            throw new CryptoAuthException(exception.getMessage());
        }
    }


    public String token(String issuer, String subject) throws CryptoAuthException {
        try {
            tokenBuilder.withIssuer(issuer).withSubject(subject);
            return tokenBuilder.sign(getHMACAlgo());
        } catch (JWTCreationException exception) {
            throw new CryptoAuthException(exception.getMessage());
        }
    }


    public String token(String issuer, String subject, String audience) throws CryptoAuthException {
        try {
            tokenBuilder.withIssuer(issuer).withSubject(subject).withAudience(audience);
            return tokenBuilder.sign(getHMACAlgo());
        } catch (JWTCreationException exception) {
            throw new CryptoAuthException(exception.getMessage());
        }
    }


    public String token() throws CryptoAuthException {
        try {
            return tokenBuilder.sign(getHMACAlgo());
        } catch (JWTCreationException exception) {
            throw new CryptoAuthException(exception.getMessage());
        }
    }

    public DecodedJWT tokenValidate(String token) throws CryptoAuthException {
        try {
            JWTVerifier.BaseVerification verification = (JWTVerifier.BaseVerification) JWT.require(getHMACAlgo());
            JWTVerifier verifier = verification.build(new JwtCustomClock());
            return verifier.verify(token);
        } catch (JWTCreationException exception) {
            throw new CryptoAuthException(exception.getMessage());
        }
    }


    public JavaJWT tokenValidUntilUTCMinutes(Integer minutes) {
        TMDateHelper tmDateHelper = new TMDateHelper();
        tokenBuilder.withExpiresAt(tmDateHelper.adjustCurrentDateWithMinute(minutes));
        return this;
    }

    public JavaJWT tokenValidUntilUTCHours(Integer hour) {
        TMDateHelper tmDateHelper = new TMDateHelper();
        tokenBuilder.withExpiresAt(tmDateHelper.adjustCurrentDateWithHour(hour));
        return this;
    }

    public static JavaJWT hmackInstance(ALGORITHM algorithm, String secret) throws CryptoAuthException {
        JavaJWT javaJWT = new JavaJWT();
        javaJWT.algorithm = algorithm;
        javaJWT.secret = secret;
        return javaJWT;
    }


//    public static JavaJWT rsaInstance(ALGORITHM algorithm, String publicKey, String privateKey) throws CryptoAuthException {
//        JavaJWT javaJWT = new JavaJWT();
//        return javaJWT;
//    }
//
//    public static JavaJWT ecdsaInstance(ALGORITHM algorithm) throws CryptoAuthException {
//        JavaJWT javaJWT = new JavaJWT();
//        return javaJWT;
//    }
//
//
//    private Algorithm getRSAAlgo() throws CryptoAuthException {
//        if (algorithm == null || publicKey == null || privateKey == null) {
//            throw new CryptoAuthException("Algorithm or public or private Key Should not be Null");
//        }
//
//        RSAPublicKey publicKey = null;
//        RSAPrivateKey privateKey = null;
//
//        if (algorithm.equals(ALGORITHM.RSA256)) {
//            return Algorithm.RSA512(publicKey, privateKey);
//        } else if (algorithm.equals(ALGORITHM.RSA384)) {
//            return Algorithm.HMAC384(secret);
//        } else if (algorithm.equals(ALGORITHM.RSA512)) {
//            return Algorithm.HMAC512(secret);
//        }
//        throw new CryptoAuthException("Invalid Algorithm Selected");
//    }
}

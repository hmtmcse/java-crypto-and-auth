package com.hmtmcse.caa.jwt;

import com.auth0.jwt.interfaces.Clock;

import java.util.Date;

public class JwtCustomClock implements Clock {

    @Override
    public Date getToday() {
        return new Date();
    }
}

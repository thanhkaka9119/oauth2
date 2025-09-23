package com.thanhmv.security.authservice.common.exception;

public class LockedAccountException extends RuntimeException {
    public LockedAccountException(String msg){ super(msg); }
}
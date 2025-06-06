package com.example.secure_password_manager_app.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Custom exception for issues encountered during OAuth2 authentication processing.
 * Extends Spring Security's AuthenticationException.
 */
public class OAuth2AuthenticationProcessingException extends AuthenticationException {

    public OAuth2AuthenticationProcessingException(String msg, Throwable t) {
        super(msg, t);
    }

    public OAuth2AuthenticationProcessingException(String msg) {
        super(msg);
    }
}
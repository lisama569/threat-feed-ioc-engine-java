package com.github.lisama569.threatfeediocenginejava.ioc.model;

/** Supported IOC indicator types. */
public enum IndicatorType {
    IP,
    DOMAIN,
    URL,
    EMAIL,
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256;

    /** Parse a type token case-insensitively; returns null when unknown. */
    public static IndicatorType fromToken(String token) {
        if (token == null) {
            return null;
        }
        String t = token.trim().toUpperCase().replace('-', '_');
        return switch (t) {
            case "IP", "IPV4", "IPV6", "IP_ADDRESS" -> IP;
            case "DOMAIN", "DOMAIN_NAME", "HOSTNAME" -> DOMAIN;
            case "URL", "URI" -> URL;
            case "EMAIL", "EMAIL_ADDRESS", "MAIL" -> EMAIL;
            case "MD5", "HASH_MD5" -> HASH_MD5;
            case "SHA1", "HASH_SHA1" -> HASH_SHA1;
            case "SHA256", "HASH_SHA256" -> HASH_SHA256;
            default -> null;
        };
    }
}

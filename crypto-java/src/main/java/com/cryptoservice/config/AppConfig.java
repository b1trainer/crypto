package com.cryptoservice.config;

public enum AppConfig {

    BASE_PATH( "/v1"),
    PORT(getEnv("PORT", "8081")),

    LIQUIBASE_CHANGELOG_FILE(getEnv("LIQUIBASE_CHANGELOG_FILE", "db/changelog/db.changelog-master.xml")),
    LIQUIBASE_CONTEXT(getEnv("LIQUIBASE_CONTEXT", "production")),

    DB_URL(getEnv("DB_URL", "jdbc:h2:file:./data/cryptoservices;AUTO_SERVER=TRUE;AUTO_SERVER_PORT=9092")),
    DB_USERNAME(getEnv("DB_USER", "sa")),
    DB_PASSWORD(getEnv("DB_PASS", "sa")),

    KS_PATH(getEnv("KS_PATH", "../certs/keystore.p12")),
    KS_PASSWORD(getEnv("KS_PASSWORD", "changeit")),
    KS_ALIAS(getEnv("KS_ALIAS", "server"));

    private final String value;

    AppConfig(String s) {
        value = s;
    }

    public String getValue() {
        return value;
    }

    private static String getEnv(String envKey, String defaultValue) {
        String env = System.getenv(envKey);
        if (env != null) return env;
        return defaultValue;
    }
}

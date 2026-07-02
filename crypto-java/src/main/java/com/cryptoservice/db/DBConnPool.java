package com.cryptoservice.db;

import com.cryptoservice.config.AppConfig;
import org.apache.commons.dbcp2.BasicDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;

public class DBConnPool {
    private static final Logger LOG = LoggerFactory.getLogger(DBConnPool.class);
    private static volatile BasicDataSource dataSource;

    private DBConnPool() {
    }

    public static synchronized DataSource getDataSource() {
        if (dataSource == null) {
            synchronized (DBConnPool.class) {
                if (dataSource == null) {
                    LOG.info("Initializing database connection pull");

                    dataSource = new BasicDataSource();

                    dataSource.setDriverClassName("org.h2.Driver");
                    dataSource.setUrl(AppConfig.DB_URL.getValue());
                    dataSource.setUsername(AppConfig.DB_USERNAME.getValue());
                    dataSource.setPassword(AppConfig.DB_PASSWORD.getValue());

                    dataSource.setInitialSize(5);
                    dataSource.setMaxTotal(20);
                    dataSource.setMaxIdle(10);
                    dataSource.setMinIdle(2);
                    dataSource.setTestOnBorrow(true);
                    dataSource.setTestWhileIdle(true);
                    dataSource.setValidationQuery("SELECT 1");

                    LOG.info("Database connection pool initialization complete");

                    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                        LOG.info("Closing database connection");
                        DBConnPool.shutdown();
                    }));
                }
            }
        }
        return dataSource;
    }

    public static Connection getConnection() throws SQLException {
        return getDataSource().getConnection();
    }

    public static synchronized void shutdown() {
        if (dataSource != null && !dataSource.isClosed()) {
            try {
                dataSource.close();
                LOG.info("Database connection pool closed");
            } catch (SQLException e) {
                LOG.error("Failed to close connection pool", e);
            }
        }
    }
}

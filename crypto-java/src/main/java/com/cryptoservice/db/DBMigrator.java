package com.cryptoservice.db;

import com.cryptoservice.config.AppConfig;
import liquibase.Contexts;
import liquibase.LabelExpression;
import liquibase.Liquibase;
import liquibase.database.Database;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.concurrent.atomic.AtomicBoolean;

public class DBMigrator {
    private static final Logger LOG = LoggerFactory.getLogger(DBMigrator.class);
    private static final AtomicBoolean migrated = new AtomicBoolean(false);

    public static void migrate(DataSource dataSource) throws Exception {
        if (!migrated.compareAndSet(false, true)) {
            LOG.info("Migrations already applied");
            return;
        }

        LOG.info("Running liquibase migrations");

        try (Connection connection = dataSource.getConnection()) {
            Database database = DatabaseFactory.getInstance()
                    .findCorrectDatabaseImplementation(new JdbcConnection(connection));

            Liquibase liquibase = new Liquibase(
                    AppConfig.LIQUIBASE_CHANGELOG_FILE.getValue(),
                    new ClassLoaderResourceAccessor(),
                    database
            );

            Contexts contexts = new Contexts(AppConfig.LIQUIBASE_CONTEXT.getValue());
            liquibase.update(contexts, new LabelExpression());
        }

        LOG.info("Liquibase migrations complete");
    }
}

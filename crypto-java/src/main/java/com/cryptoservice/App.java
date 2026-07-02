package com.cryptoservice;

import com.cryptoservice.config.AppConfig;
import com.cryptoservice.controller.CryptoController;
import com.cryptoservice.crypto.CryptoUtil;
import com.cryptoservice.db.DBConnPool;
import com.cryptoservice.db.DBMigrator;
import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;

public class App {
    private static final Logger LOG = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) throws Exception {
        CryptoUtil.registerProviders();
        DataSource dataSource = DBConnPool.getDataSource();
        DBMigrator.migrate(dataSource);

        Tomcat tomcat = configureServer();
        tomcat.start();
        tomcat.getServer().await();
    }

    // todo добавить возможность работы по TLS/mTLS
    private static Tomcat configureServer() {
        LOG.info("Creating web server");

        int port = Integer.parseInt(AppConfig.PORT.getValue());
        String path = AppConfig.BASE_PATH.getValue();

        Tomcat tomcat = new Tomcat();
        tomcat.setPort(port);
        tomcat.getConnector();
        Context ctx = tomcat.addContext(path, null);
        ServletContainer jerseyServlet = new ServletContainer(
                new ResourceConfig()
                        .register(MultiPartFeature.class)
                        .register(CryptoController.class)
        );
        Tomcat.addServlet(ctx, "jerseyServlet", jerseyServlet);
        ctx.addServletMappingDecoded("/*", "jerseyServlet");

        LOG.info("Application configured on http://localhost:{}", port);

        return tomcat;
    }
}

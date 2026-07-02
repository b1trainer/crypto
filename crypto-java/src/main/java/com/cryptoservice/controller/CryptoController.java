package com.cryptoservice.controller;

import com.cryptoservice.config.AppConfig;
import com.cryptoservice.dto.CryptoRequest;
import com.cryptoservice.dto.CryptoResponse;
import com.cryptoservice.service.CryptoService;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.io.IOUtils;
import org.apache.tika.Tika;
import org.glassfish.jersey.media.multipart.FormDataContentDisposition;
import org.glassfish.jersey.media.multipart.FormDataParam;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Path("/crypto")
@Consumes(MediaType.MULTIPART_FORM_DATA)
public class CryptoController {
    private static final Logger LOG = LoggerFactory.getLogger(CryptoController.class);

    private final CryptoService service;
    private final Tika tika;

    public CryptoController() throws Exception {
        this.service = new CryptoService(
                AppConfig.KS_PATH.getValue(),
                AppConfig.KS_PASSWORD.getValue(),
                AppConfig.KS_ALIAS.getValue()
        );
        this.tika = new Tika();
    }

    @POST
    @Path("/sign")
    public Response sign(
            @FormDataParam("file") InputStream fileInputStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail,
            @QueryParam("detached") String detachedStr
    ) throws IOException {

        boolean detached = Boolean.parseBoolean(detachedStr);
        byte[] data = IOUtils.toByteArray(fileInputStream);
        String fileName = fileDetail.getFileName();
        String mimeType = tika.detect(data, fileName);

        CryptoRequest request = new CryptoRequest(
                fileName,
                mimeType,
                data,
                detached
        );

        try {
            LOG.info("Sign request received, detached={}", detached);
            CryptoResponse response = service.sign(request);

            if (detached) {
                return Response.ok(response).build();
            } else {
                return Response.ok(response.getResult())
                        .type("application/pkcs7-signature")
                        .header("Content-Disposition", "attachment; filename=\"" + fileDetail.getFileName() + ".p7s\"")
                        .build();
            }
        } catch (Exception e) {
            LOG.error("Sign failed", e);
            return Response.status(500).entity(error(e)).build();
        }
    }

    @POST
    @Path("/verify")
    public Response verify(
            @FormDataParam("file") InputStream fileInputStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail
    ) throws IOException {

        byte[] data = IOUtils.toByteArray(fileInputStream);
        String fileName = fileDetail.getFileName();
        String mimeType = tika.detect(data, fileName);

        CryptoRequest request = new CryptoRequest(
                fileName,
                mimeType,
                data
        );

        try {
            LOG.info("Verify request received");
            CryptoResponse response = service.verify(request);
            return Response.ok(response)
                    .type("application/json")
                    .build();
        } catch (Exception e) {
            LOG.error("Verify failed", e);
            return Response.status(500).entity(error(e)).build();
        }
    }

    @POST
    @Path("/encrypt")
    public Response encrypt(
            @FormDataParam("file") InputStream fileInputStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail
    ) throws IOException {

        byte[] data = IOUtils.toByteArray(fileInputStream);
        String fileName = fileDetail.getFileName();
        String mimeType = tika.detect(data, fileName);

        CryptoRequest request = new CryptoRequest(
                fileName,
                mimeType,
                data
        );

        try {
            LOG.info("Encrypt request received");
            CryptoResponse response = service.encrypt(request);
            return Response.ok(response.getResult())
                    .type("application/pkcs7-mime; smime-type=enveloped-data")
                    .header("Content-Disposition", "attachment; filename=\"" + fileDetail.getFileName() + ".p7m\"")
                    .build();
        } catch (Exception e) {
            LOG.error("Encrypt failed", e);
            return Response.status(500).entity(error(e)).build();
        }
    }

    @POST
    @Path("/decrypt")
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response decrypt(
            @FormDataParam("file") InputStream fileInputStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail
    ) throws IOException {

        byte[] data = IOUtils.toByteArray(fileInputStream);
        String fileName = fileDetail.getFileName();

        CryptoRequest request = new CryptoRequest(
                fileName,
                null,
                data
        );

        try {
            LOG.info("Decrypt request received");
            CryptoResponse response = service.decrypt(request);
            return Response.ok(response.getResult())
                    .type(response.getContentType())
                    .header("Content-Disposition", "attachment; filename=\"" + fileDetail.getFileName())
                    .build();
        } catch (Exception e) {
            LOG.error("Decrypt failed", e);
            return Response.status(500).entity(error(e)).build();
        }
    }

    @POST
    @Path("/hash")
    public Response hash(
            @FormDataParam("file") InputStream fileInputStream,
            @FormDataParam("file") FormDataContentDisposition fileDetail
    ) throws IOException {

        byte[] data = IOUtils.toByteArray(fileInputStream);
        String fileName = fileDetail.getFileName();
        String mimeType = tika.detect(data, fileName);

        CryptoRequest request = new CryptoRequest(
                fileName,
                mimeType,
                data
        );

        try {
            LOG.info("Hash request received");
            String response = service.hash(request);
            return Response.ok(response)
                    .type("application/json")
                    .build();
        } catch (Exception e) {
            LOG.error("Hash failed", e);
            return Response.status(500).entity(error(e)).build();
        }
    }

    @DELETE
    @Path("/files")
    @Produces(MediaType.APPLICATION_JSON)
    public Response delete(@QueryParam("name") String fileName) {
        try {
            boolean response = service.deleteDocument(fileName);
            return Response.ok(response)
                    .type("application/json")
                    .build();
        } catch (Exception e) {
            return Response.status(500).entity(error(e)).build();
        }
    }

    @GET
    @Path("/operations")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getOperations() {
        try {
            List<?> logs = service.getOperations();
            Map<String, Object> result = new HashMap<>();
            result.put("operations", logs);
            return Response.ok(result).build();
        } catch (Exception e) {
            LOG.error("Get operations failed", e);
            return Response.status(500).entity(error(e)).build();
        }
    }

    @GET
    @Path("/download")
    public Response download(@QueryParam("url") String url) {
        return Response.status(Response.Status.NOT_IMPLEMENTED)
                .entity("{\"error\":\"Not implemented yet\"}")
                .build();
    }

    private Map<String, String> error(Exception e) {
        Map<String, String> err = new HashMap<>();
        err.put("error", e.getMessage());
        return err;
    }

}

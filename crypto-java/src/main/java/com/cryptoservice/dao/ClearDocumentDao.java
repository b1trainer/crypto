package com.cryptoservice.dao;

import com.cryptoservice.db.DBConnPool;
import com.cryptoservice.model.ClearDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;

public class ClearDocumentDao {

    private static final Logger LOG = LoggerFactory.getLogger(ClearDocumentDao.class);

    private ClearDocumentDao() {
    }

    public static Long save(ClearDocument doc) {
        String sql = "INSERT INTO documents (name, content_type, data, size) VALUES (?, ?, ?, ?)";

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)
        ) {
            ps.setString(1, doc.getName());
            ps.setString(2, doc.getContentType());
            ps.setBytes(3, doc.getData());
            ps.setLong(4, doc.getSize());

            if (ps.executeUpdate() == 0) {
                throw new SQLException("Creating document failed, no rows affected.");
            }

            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    Long id = rs.getLong(1);
                    doc.setId(id);
                    LOG.debug("Document saved with id={}", id);
                    return id;
                }
            }
            throw new SQLException("Creating document failed, no ID obtained.");

        } catch (SQLException e) {
            LOG.error("Failed to save document", e);
            throw new RuntimeException("Failed to save document", e);
        }
    }

    public static String getOriginalContentType(String name) {
        String sql = "SELECT content_type FROM documents WHERE name = ?";

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)
        ) {
            ps.setString(1, name);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1);
                }
            }
            return null;

        } catch (SQLException e) {
            LOG.error("Failed to save document", e);
            throw new RuntimeException("Failed to save document", e);
        }
    }

    public static boolean deleteByName(String name) {
        String sql = "DELETE FROM documents WHERE NAME = ?";

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)
        ) {
            ps.setString(1, name);
            return  ps.execute();
        } catch (SQLException e) {
            LOG.error("Failed to delete document by name={}", name, e);
            throw new RuntimeException("Failed to get document", e);
        }
    }
}

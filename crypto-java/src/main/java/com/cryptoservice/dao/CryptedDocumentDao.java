package com.cryptoservice.dao;

import com.cryptoservice.db.DBConnPool;
import com.cryptoservice.model.CryptedDocument;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.ZoneOffset;

public class CryptedDocumentDao {

    private static final Logger LOG = LoggerFactory.getLogger(CryptedDocumentDao.class);

    private CryptedDocumentDao() {}

    /**
     * Save result and return generated ID.
     */
    public static Long save(CryptedDocument cryptedDocument) {
        String sql = "INSERT INTO cryptedDocuments (document_id, document_name, operation_type, data, size) VALUES (?, ?, ?, ?, ?)";

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            ps.setLong(1, cryptedDocument.getDocumentId());
            ps.setString(2, cryptedDocument.getDocumentName());
            ps.setString(3, cryptedDocument.getOperationType());
            ps.setBytes(4, cryptedDocument.getData());
            ps.setLong(5, cryptedDocument.getSize());

            int affected = ps.executeUpdate();
            if (affected == 0) {
                throw new SQLException("Creating result failed, no rows affected.");
            }

            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    Long id = rs.getLong(1);
                    cryptedDocument.setId(id);
                    LOG.debug("Result saved with id={}", id);
                    return id;
                }
            }
            throw new SQLException("Creating result failed, no ID obtained.");

        } catch (SQLException e) {
            LOG.error("Failed to save result", e);
            throw new RuntimeException("Failed to save result", e);
        }
    }

    /**
     * Get results by document name.
     */
    public static CryptedDocument getByDocumentName(String documentName) {
        String sql = "SELECT * FROM cryptedDocuments WHERE document_name = ? ORDER BY created_at DESC";

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, documentName);

            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    CryptedDocument r = new CryptedDocument();
                    r.setId(rs.getLong("id"));
                    r.setDocumentId(rs.getLong("document_id"));
                    r.setDocumentName(rs.getString("document_name"));
                    r.setOperationType(rs.getString("operation_type"));
                    r.setData(rs.getBytes("data"));
                    r.setSize(rs.getLong("size"));
                    Timestamp ts = rs.getTimestamp("created_at");
                    r.setCreatedAt(ts != null ? ts.toInstant().atOffset(ZoneOffset.UTC) : null);
                    return r;
                }
            }
        } catch (SQLException e) {
            LOG.error("Failed to get results by document name={}", documentName, e);
            throw new RuntimeException("Failed to get results", e);
        }

        return null;
    }

    public static boolean deleteByName(String name) {
        String sql = "DELETE FROM cryptedDocuments WHERE document_name = ?";

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)
        ) {
            ps.setString(1, name);
            return ps.execute();
        } catch (SQLException e) {
            LOG.error("Failed to delete crypted document by name={}", name, e);
            throw new RuntimeException("Failed to get document", e);
        }
    }
}

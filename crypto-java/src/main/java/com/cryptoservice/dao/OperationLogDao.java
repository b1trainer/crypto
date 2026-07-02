package com.cryptoservice.dao;

import com.cryptoservice.db.DBConnPool;
import com.cryptoservice.model.OperationLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

public class OperationLogDao {

    private static final Logger LOG = LoggerFactory.getLogger(OperationLogDao.class);

    private OperationLogDao() {
    }

    public static void save(OperationLog log) {
        String saveSql = "INSERT INTO operations_log (operation_type, status, details, duration_ms) VALUES (?, ?, ?, ?)";

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement stmt = conn.prepareStatement(saveSql)
        ) {
            stmt.setString(1, log.getOperationType());
            stmt.setString(2, log.getStatus());
            stmt.setString(3, log.getDetails());
            stmt.setLong(4, log.getDurationMs());

            if (stmt.executeUpdate() == 0) {
                throw new SQLException("Creating log entry failed, no rows affected.");
            }
        } catch (SQLException e) {
            LOG.error("Failed to save operation log", e);
        }
    }

    public static List<OperationLog> getAll() {
        String sql = "SELECT * FROM operations_log ORDER BY created_at DESC";

        List<OperationLog> logs = new ArrayList<>();

        try (Connection conn = DBConnPool.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)
        ) {
            mapToModel(logs, rs);
        } catch (SQLException e) {
            LOG.error("Failed to get operation logs", e);
        }

        return logs;
    }

    public static List<OperationLog> getByOperationType(String operationType) {
        String sql = "SELECT * FROM operations_log WHERE operation_type = ? ORDER BY created_at DESC";

        List<OperationLog> logs = new ArrayList<>();

        try (Connection conn = DBConnPool.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)
        ) {
            ps.setString(1, operationType);
            try (ResultSet rs = ps.executeQuery()) {
                mapToModel(logs, rs);
            }
        } catch (SQLException e) {
            LOG.error("Failed to get operation logs by type={}", operationType, e);
        }
        return logs;
    }

    private static void mapToModel(List<OperationLog> logs, ResultSet rs) throws SQLException {
        while (rs.next()) {
            OperationLog log = new OperationLog();
            log.setId(rs.getLong("id"));
            log.setOperationType(rs.getString("operation_type"));
            log.setStatus(rs.getString("status"));
            log.setDetails(rs.getString("details"));
            log.setDurationMs(rs.getLong("duration_ms"));
            Timestamp ts = rs.getTimestamp("created_at");
            log.setCreatedAt(ts != null ? ts.toInstant().atOffset(ZoneOffset.UTC).toString() : null);
            logs.add(log);
        }
    }
}

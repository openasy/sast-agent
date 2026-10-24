import java.sql.Connection;
import java.sql.Statement;

class Find {
    void find(Connection c, String name) throws Exception {
        Statement s = c.createStatement();
        // ruleid: openasy.java.sql-injection
        s.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: openasy.java.sql-injection
        c.prepareStatement(String.format("DELETE FROM users WHERE name = '%s'", name));
        // ok: openasy.java.sql-injection
        c.prepareStatement("SELECT * FROM users WHERE name = ?").setString(1, name);
    }
}

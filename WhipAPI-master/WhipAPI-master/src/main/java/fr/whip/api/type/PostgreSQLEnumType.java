package fr.whip.api.type;

import fr.whip.api.model.LicenseStatus;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.usertype.UserType;

import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;

public class PostgreSQLEnumType implements UserType<LicenseStatus> {

    @Override
    public int getSqlType() {
        return Types.VARCHAR;
    }

    @Override
    public Class<LicenseStatus> returnedClass() {
        return LicenseStatus.class;
    }

    @Override
    public boolean equals(LicenseStatus x, LicenseStatus y) {
        return x == y;
    }

    @Override
    public int hashCode(LicenseStatus x) {
        return x.hashCode();
    }

    @Override
    public LicenseStatus nullSafeGet(ResultSet rs, int position,
                                     SharedSessionContractImplementor session, Object owner) throws SQLException {
        String name = rs.getString(position);
        return name == null ? null : LicenseStatus.valueOf(name);
    }

    @Override
    public void nullSafeSet(PreparedStatement st, LicenseStatus value, int index,
                            SharedSessionContractImplementor session) throws SQLException {
        if (value == null) {
            st.setNull(index, Types.OTHER);
        } else {
            st.setObject(index, value.name(), Types.OTHER);
        }
    }

    @Override
    public LicenseStatus deepCopy(LicenseStatus value) {
        return value;
    }

    @Override
    public boolean isMutable() {
        return false;
    }

    @Override
    public Serializable disassemble(LicenseStatus value) {
        return value.name();
    }

    @Override
    public LicenseStatus assemble(Serializable cached, Object owner) {
        return LicenseStatus.valueOf((String) cached);
    }

    @Override
    public LicenseStatus replace(LicenseStatus original, LicenseStatus target, Object owner) {
        return original;
    }
}
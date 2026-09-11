"""
PostgreSQL immutability trigger installation helper for consuming applications.
"""

from django.db import connection


def install_postgres_immutability_trigger(table_name: str) -> None:
    """
    Installs a PostgreSQL BEFORE UPDATE OR DELETE trigger raising an exception.
    Permits no carve-outs.
    """
    trigger_function = f"osivault_prevent_immutability_{table_name}"
    trigger_name = f"trg_osivault_immutable_{table_name}"

    sql = f"""
    CREATE OR REPLACE FUNCTION {trigger_function}()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'OSIVault audit entries are immutable and cannot be updated or deleted from table %', TG_TABLE_NAME;
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS {trigger_name} ON {table_name};

    CREATE TRIGGER {trigger_name}
    BEFORE UPDATE OR DELETE ON {table_name}
    FOR EACH ROW EXECUTE FUNCTION {trigger_function}();
    """

    with connection.cursor() as cursor:
        cursor.execute(sql)

#!/bin/bash

# Start SQL Server in the background
/opt/mssql/bin/sqlservr &
pid=$!

# Wait for SQL Server to be ready
echo "Waiting for MSSQL to start..."
for i in {1..60}; do
    /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PASSWORD" -C -Q "SELECT 1" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "MSSQL is ready"
        break
    fi
    sleep 1
done

# Run init script if it exists and database doesn't exist yet
if [ -f /seed.sql ]; then
    echo "Running init script..."
    /opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P "$SA_PASSWORD" -C -i /seed.sql
    echo "Init script completed"
fi

# Wait for SQL Server process
wait $pid

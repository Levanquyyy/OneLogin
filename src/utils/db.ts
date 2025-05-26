import sql from 'mssql';
import dotenv from "dotenv";


// Load environment variables from .env file
dotenv.config();
const config: sql.config = {
    user: process.env.SQL_DB_USERNAME,
    password: process.env.SQL_DB_PASSWORD,
    server: String(process.env.SQL_DB_SERVER),
    database: process.env.SQL_DB_NAME,
    port: parseInt(process.env.SQL_DB_PORT || '1433'),
    options: {
        encrypt: true,
        trustServerCertificate: true,
    },
    pool: {
        max: 10,
        min: 0,
        idleTimeoutMillis: 30000
    }
};

export const connectToDB = async () => {
    try {
        const pool = await sql.connect(config);
        console.log('Connected to SQL Server' , process.env.SQL_DB_USERNAME);
        return pool;
    } catch (err) {
        console.error('Database connection failed:', err);
        throw err;
    }
};

export default sql;

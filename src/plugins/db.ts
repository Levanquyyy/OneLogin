import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';
import { connectToDB } from '~/utils/db';
import sql from 'mssql';

const dbPlugin = fp(async (fastify: FastifyInstance) => {
    try {
        const pool = await connectToDB();
        fastify.decorate('db', pool);
        fastify.log.info('Database connected successfully');
    } catch (err) {
        fastify.log.error('Failed to connect to the database:', err);
        throw err;
    }
});

declare module 'fastify' {
    interface FastifyInstance {
        db: sql.ConnectionPool;
    }
}

export default dbPlugin;

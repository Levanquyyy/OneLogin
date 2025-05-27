import { FastifyReply, FastifyRequest } from 'fastify';

export const authMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
    try {
        const tokenKey = request.headers.authorization?.split(' ')[1];
        if (!tokenKey) {
            return reply.status(401).send({ error: 'No session key provided' });
        }

        const dbRequest = request.server.db.request();
        dbRequest.input('TokenKey', tokenKey);
        const result = await dbRequest.query('SELECT TokenValue FROM Sessions WHERE TokenKey = @TokenKey');

        if (result.recordset.length === 0) {
            return reply.status(401).send({ error: 'Session expired or invalidated' });
        }

        const jwtToken = result.recordset[0].TokenValue;
        const payload = await request.server.jwt.verify(jwtToken);

        (request as any).user = payload;

    } catch (error) {
        return reply.status(401).send({ error: 'Unauthorized' });
    }
};


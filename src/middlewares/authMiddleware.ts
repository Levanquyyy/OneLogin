import { FastifyReply, FastifyRequest } from 'fastify';

export const authMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
    try {
        const token = request.headers.authorization?.split(' ')[1];
        if (!token) {
            return reply.status(401).send({ error: 'No token provided' });
        }
        const payload: any = await request.server.jwt.verify(token);
        (request as any).user = payload;
    } catch (error) {
        return reply.status(401).send({ error: 'Unauthorized' });
    }
};

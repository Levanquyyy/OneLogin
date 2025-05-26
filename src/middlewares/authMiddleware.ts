import {FastifyReply, FastifyRequest} from 'fastify';

const activeTokens = new Set<string>();
const userSessionMap = new Map<number | string, string>();
export const authMiddleware = async (request: FastifyRequest, reply: FastifyReply) => {
    try {
        await request.jwtVerify();
        const token = request.headers.authorization?.split(' ')[1] || '';


        if (!activeTokens.has(token)) {
            return reply.status(401).send({error: 'Session expired or invalidated'});
        }
    } catch (error) {
        return reply.status(401).send({error: 'Unauthorized'});
    }
};

export {activeTokens, userSessionMap};

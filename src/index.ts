import Fastify from 'fastify';
import dbPlugin from '~/plugins/db';
import userController from '~/controllers/userController';
import fastifyJwt from "@fastify/jwt";

const fastify = Fastify({
    logger: true,
});

fastify.register(dbPlugin);
fastify.register(fastifyJwt, {
    secret: 'supersecret',
});
fastify.register(userController, {prefix: '/api/v1'});

const start = async () => {
    try {
        await fastify.listen({port: 3000});
        console.log('Server is running at http://localhost:3000');
    } catch (err) {
        fastify.log.error(err);
        process.exit(1);
    }
};

start();

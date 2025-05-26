"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const getAllUser = (fastify, options, done) => {
    fastify.get('/user', (request, reply) => {
        return {
            message: "Check"
        };
    });
    done();
};
exports.default = getAllUser;

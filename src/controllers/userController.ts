import {FastifyInstance, FastifyPluginOptions, FastifyReply, FastifyRequest} from 'fastify';
import bcrypt from 'bcrypt';

import {activeTokens, authMiddleware, userSessionMap} from '~/middlewares/authMiddleware';

const checkPostUserRequest = {
    body: {
        type: 'object',
        properties: {
            memberAccount: {type: 'string'},
            memberNickName: {type: 'string'}
        },
        required: ['memberAccount', 'memberNickName']
    },
    response: {
        200: {
            type: 'object',
            properties: {
                message: {type: 'string'},
                userId: {type: 'integer'}
            }
        }
    }
};

const checkLoginRequest = {
    body: {
        type: 'object',
        properties: {
            memberAccount: {type: 'string'},
            memberNickName: {type: 'string'}
        },
        required: ['memberAccount', 'memberNickName']
    },
    response: {
        200: {
            type: 'object',
            properties: {
                message: {type: 'string'},
                userId: {type: 'integer'},
                token: {type: 'string'}
            }
        }
    }
};

const checkresponse = {
    response: {
        200: {
            type: 'object',
            properties: {
                users: {
                    type: 'array',
                    items: {
                        type: 'object',
                        properties: {
                            IdUser: {type: 'integer'},
                            memberAccount: {type: 'string'},
                            memberNickName: {type: 'string'}
                        },
                        required: ['IdUser', 'memberAccount', 'memberNickName']
                    }
                }
            }
        }
    }
};

interface JwtPayload {
    userId: number | string;
    memberNickName: string;
}

const postUser = async (fastify: FastifyInstance, options: FastifyPluginOptions) => {
    fastify.post('/signup', {schema: checkPostUserRequest}, async (request, reply) => {
        const {memberAccount, memberNickName} = request.body as { memberAccount: string; memberNickName: string };

        try {
            const hashedPassword = await bcrypt.hash(memberAccount, 10);
            const dbRequest = fastify.db.request();

            dbRequest.input('i_memberAccount', hashedPassword);
            dbRequest.input('i_memberNickName', memberNickName);

            const result = await dbRequest.execute('Proc_UsersRegister_Insert');
            const userId = result.returnValue;

            return reply.send({message: 'User created successfully', userId});
        } catch (error: any) {
            reply.status(500).send({error: 'Failed to create user', details: error.message});
        }
    });
};


export const getAllUser = async (fastify: FastifyInstance, options: FastifyPluginOptions) => {
    fastify.get('/user', {
        preHandler: authMiddleware,
        schema: checkresponse
    }, async (request, reply) => {
        try {
            const dbRequest = fastify.db.request();
            const result = await dbRequest.execute('SelectAllCustomers');
            return reply.send({users: result.recordset});
        } catch (error: any) {
            reply.status(500).send({error: 'Failed to fetch users', details: error.message});
        }
    });
};


export const loginUser = async (fastify: FastifyInstance, options: FastifyPluginOptions) => {
    fastify.post('/login', {schema: checkLoginRequest}, async (request, reply) => {
        const {memberAccount, memberNickName} = request.body as {
            memberAccount: string;
            memberNickName: string;
        };


        try {
            const dbRequest = fastify.db.request();
            dbRequest.input('i_memberNickName', memberNickName);

            const result = await dbRequest.execute('Proc_ValidateUser');

            if (result.recordset.length === 0) {
                return reply.status(401).send({error: 'Invalid credentials'});
            }

            const user = result.recordset[0];
            const isPasswordValid = await bcrypt.compare(memberAccount, user.memberAccount);
            if (!isPasswordValid) {
                return reply.status(401).send({error: 'Invalid credentials'});

            }

            const userId = user.IdUser;

            if (userSessionMap.has(userId)) {
                const oldToken = userSessionMap.get(userId);
                if (oldToken) {
                    activeTokens.delete(oldToken);
                    fastify.log.info(`User ${userId} logged in elsewhere. Old token ${oldToken.substring(0, 10)}... invalidated.`);
                }
            }
            const token = fastify.jwt.sign({memberNickName, userId});
            activeTokens.add(token);
            userSessionMap.set(userId, token);

            return reply.send({
                message: 'Login successful',
                userId: userId,
                token
            });
        } catch (error: any) {
            fastify.log.error(error);
            return reply.status(500).send({error: 'Login failed', details: error.message});
        }
    });
};


export const logoutUser = async (fastify: FastifyInstance, options: FastifyPluginOptions) => {
    fastify.post('/logout', {
        preHandler: authMiddleware
    }, async (request, reply) => {
        const token = request.headers.authorization?.split(' ')[1];

        if (!token) {
            return reply.status(401).send({error: 'No token provided'});
        }

        try {
            const decoded = await request.jwtVerify<JwtPayload>();

            if (activeTokens.has(token)) {
                activeTokens.delete(token);



                if (decoded && decoded?.userId) {
                    if (userSessionMap.get(decoded.userId) === token) {
                        userSessionMap.delete(decoded.userId);
                    }
                }
                return reply.send({message: 'Logged out successfully'});
            } else {
                // Token was already inactive (e.g., logged out elsewhere, or expired and caught by jwtVerify)
                return reply.status(400).send({message: 'Session already inactive or token invalid'});
            }

        } catch (error: any) {
            fastify.log.error(error, "Logout error");
            return reply.status(500).send({error: 'Logout failed', details: error.message});
        }
    });
};


export default async (fastify: FastifyInstance, options: FastifyPluginOptions) => {
    await getAllUser(fastify, options);
    await postUser(fastify, options);
    await loginUser(fastify, options);
    await logoutUser(fastify, options);
};

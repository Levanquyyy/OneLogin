import {FastifyInstance, FastifyPluginOptions} from 'fastify';
import bcrypt from 'bcrypt';
import {authMiddleware} from '~/middlewares/authMiddleware';

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
            const hashedAccount = await bcrypt.hash(memberAccount, 10);
            const dbRequest = fastify.db.request();

            dbRequest.input('i_memberAccount', hashedAccount);
            dbRequest.input('i_memberNickName', memberNickName);

            const result = await dbRequest.execute('Proc_UsersRegister_Insert');
            const userId = result.returnValue;

            return reply.send({message: 'User created successfully', userId});
        } catch (error: any) {
            return reply.status(500).send({error: 'Failed to create user', details: error.message});
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

            const token = fastify.jwt.sign({ memberNickName, userId });
            const decoded: any = fastify.jwt.decode(token);
            console.log("Decoded JWT:", decoded);
            const iat = decoded.iat;


            const dbRequestSession = fastify.db.request();
            dbRequestSession.input('TokenKey', iat);
            dbRequestSession.input('TokenValue', token);
            await dbRequestSession.query('INSERT INTO Sessions (TokenKey, TokenValue) VALUES (@TokenKey, @TokenValue)');

            return reply.send({
                message: 'Login successful',
                userId: userId,
                tokenKey: iat
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
        const tokenKey = request.headers.authorization?.split(' ')[1];

        if (!tokenKey) {
            return reply.status(401).send({error: 'No token provided'});
        }

        try {
            await request.jwtVerify<JwtPayload>();

            const dbRequest = fastify.db.request();
            dbRequest.input('tokenKey', tokenKey);
            const result = await dbRequest.query('DELETE FROM Sessions WHERE TokenKey = @TokenKey');

            if (result.rowsAffected && result.rowsAffected[0] > 0) {
                return reply.send({message: 'Logged out successfully'});
            } else {
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

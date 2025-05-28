export const sessionRepository = {
    findSession: async (db: any, userId: number, jwtId: string) => {
        const dbRequest = db.request();
        dbRequest.input('UserId', userId);
        dbRequest.input('JwtId', jwtId);
        const result = await dbRequest.execute('Proc_Session_Validate');
        return result.returnValue === 1;
    },
    insertSession: async (db: any, userId: number, jwtId: string, token: string, refreshToken: string) => {
        const dbRequest = db.request();
        dbRequest.input('UserId', userId);
        dbRequest.input('JwtId', jwtId);
        dbRequest.input('Token', token);
        dbRequest.input('RefreshToken', refreshToken);
        await dbRequest.execute('Proc_Session_Insert');
    },
    findByRefreshToken: async (db: any, refreshToken: string) => {
        const dbRequest = db.request();
        dbRequest.input('RefreshToken', refreshToken);
        const result = await dbRequest.execute('Proc_Session_FindByRefreshToken');
        return result.recordset[0];
    },
    deleteSessionsByUserId: async (db: any, userId: number) => {
        const dbRequest = db.request();
        dbRequest.input('UserId', userId);
        await dbRequest.execute('Proc_Session_DeleteByUserId');
    },
    updateSessionJwt: async (db: any, userId: number, refreshToken: string, newJwtId: string, newToken: string) => {
        const dbRequest = db.request();
        dbRequest.input('UserId', userId);
        dbRequest.input('RefreshToken', refreshToken);
        dbRequest.input('NewJwtId', newJwtId);
        dbRequest.input('NewToken', newToken);
        await dbRequest.execute('Proc_Session_UpdateJwt');
    }
};

export const sessionRepository = {
    findSession: async (db: any, userId: number, jwtId: string) => {
        const dbRequest = db.request();
        dbRequest.input('UserId', userId);
        dbRequest.input('JwtId', jwtId);
        const result = await dbRequest.execute('Proc_Session_Validate');
        return result.returnValue === 1;
    },
    insertSession: async (db: any, userId: number, jwtId: string, token: string) => {
        const dbRequest = db.request();
        dbRequest.input('UserId', userId);
        dbRequest.input('JwtId', jwtId);
        dbRequest.input('Token', token);
        await dbRequest.execute('Proc_Session_Insert');
    },
    deleteSessionsByUserId: async (db: any, userId: number) => {
        const dbRequest = db.request();
        dbRequest.input('UserId', userId);
        await dbRequest.execute('Proc_Session_DeleteByUserId');
    }
};

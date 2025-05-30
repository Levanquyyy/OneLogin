const executeProcedure = async (db: any, procedureName: string) => {
    const dbRequest = db.request();
    const result = await dbRequest.execute(procedureName);
    return result.recordset;
};


export const getAllUsers = async (db: any) => {
    return await executeProcedure(db, 'SelectAllCustomers');
};
export const GetUserByIdTreeRepo = async (db: any, userId: number) => {
    const dbRequest = db.request();
    dbRequest.input('i_IdUser', userId);
    const result = await dbRequest.execute('Proc_Sort_User');
    return result.recordset;
}

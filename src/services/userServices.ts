import {getAllUsers, GetUserByIdTreeRepo} from '~/repositories/userRepository';

export const fetchGetAllUsers = async (db: any) => {
    return await getAllUsers(db);
}
export const GetUserByIdTreeSerVices = async (db: any, i_IdUser: number) => {
    return await GetUserByIdTreeRepo(db, i_IdUser);
}

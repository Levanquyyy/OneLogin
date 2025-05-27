import { sessionRepository } from '~/repositories/sessionRepository';

export const validateSession = async (db: any, userId: number, jwtId: string) => {
    return await sessionRepository.findSession(db, userId, jwtId);
};

export const deleteSessionsByUserId = async (db: any, userId: number) => {
    await sessionRepository.deleteSessionsByUserId(db, userId);
};

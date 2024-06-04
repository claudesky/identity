import { sequelize } from './sequelize-service'
import { TokenRepositorySequelize } from '../repositories/token/token-repository-sequelize'

export const tokenRepositoryService = new TokenRepositorySequelize(sequelize)

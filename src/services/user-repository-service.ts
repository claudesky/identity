import { Sequelize } from 'sequelize'
import { UserRepositorySequelize } from '../repositories/user/user-repository-sqlite'

import { sequelize } from './sequelize-service'

export const userRepositoryService = new UserRepositorySequelize(sequelize)

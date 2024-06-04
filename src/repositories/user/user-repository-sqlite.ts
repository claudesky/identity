import { Sequelize, DataTypes, Model } from 'sequelize'
import {
  IUserRepository,
  RegisterByEmailAttributes,
  RegisterByPhoneNumberAttributes,
  User as IUser,
  UserAttributes,
} from './iuser-repository'
import { randomUUID } from 'crypto'
import {
  NotFoundException,
  NotImplementedException,
} from '../../modules/exceptions'

export class User extends Model implements UserAttributes {
  declare id: string
  declare email: string
  declare email_verified: boolean
  declare phone_number: string | null
  declare phone_number_verified: boolean
  declare password: string
  declare name: string
  declare zoneinfo: string | undefined
}

export class UserRepositorySequelize implements IUserRepository {
  ready: Promise<boolean>
  constructor(sequelize: Sequelize) {
    User.init(
      {
        id: {
          type: DataTypes.UUID,
          allowNull: false,
          primaryKey: true,
        },
        email: {
          type: DataTypes.STRING,
          unique: 'UQ_user_email_phone_number',
        },
        email_verified: DataTypes.BOOLEAN,
        phone_number: {
          type: DataTypes.STRING,
          unique: 'UQ_user_email_phone_number',
        },
        phone_number_verified: DataTypes.BOOLEAN,
        password: {
          type: DataTypes.STRING,
          allowNull: false,
        },
        name: {
          type: DataTypes.STRING,
          allowNull: false,
        },
        zoneinfo: DataTypes.STRING,
      },
      { sequelize }
    )
    this.ready = User.sync().then(() => true)
  }

  async getUserByEmail(email: string): Promise<IUser> {
    const user = await User.findOne({ where: { email } })

    if (user === null) throw new NotFoundException()

    return user
  }

  async getUserByPhoneNumber(phone_number: string): Promise<IUser> {
    throw new NotImplementedException()
  }

  async registerByEmail(attributes: RegisterByEmailAttributes): Promise<IUser> {
    const user = new User({ ...attributes, id: randomUUID() })
    await user.save()
    return user
  }

  async registerByPhoneNumber(
    attributes: RegisterByPhoneNumberAttributes
  ): Promise<IUser> {
    throw new NotImplementedException()
  }
}

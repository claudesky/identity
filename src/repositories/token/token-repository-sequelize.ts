import { UUID } from 'crypto'
import {
  InvalidLastIssuedException,
  ITokenRepository,
  TokenNotFoundException,
} from './itoken-repository'

import { DataTypes, Model, Sequelize } from 'sequelize'

class Token extends Model {
  declare id: string
  declare subject: string
  declare lastIssued: string
}

export class TokenRepositorySequelize implements ITokenRepository {
  ready: Promise<boolean>
  constructor(sequelize: Sequelize) {
    Token.init(
      {
        id: {
          type: DataTypes.UUID,
          allowNull: false,
          primaryKey: true,
        },
        subject: DataTypes.STRING,
        lastIssued: DataTypes.UUID,
      },
      { sequelize }
    )
    this.ready = Token.sync().then(() => true)
  }

  async add(id: UUID, subject: string): Promise<void> {
    const token = new Token({
      id,
      subject,
      lastIssued: id,
    })

    await token.save()
  }

  async reissue(
    familyId: UUID,
    oldId: UUID,
    subject: string,
    newId: UUID
  ): Promise<void> {
    const token = await Token.findByPk(familyId)

    if (token === null) throw new TokenNotFoundException()

    if (token.lastIssued != oldId || token.subject != subject) {
      await token.destroy()
      throw new InvalidLastIssuedException()
    }

    await token.update({ lastIssued: newId })
  }

  async delete(familyId: UUID): Promise<void> {
    const token = await Token.findByPk(familyId)

    if (token === null) throw new TokenNotFoundException()

    await token.destroy()
  }
}

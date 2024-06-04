import { UUID } from 'crypto'

export interface ITokenRepository {
  ready: Promise<boolean>
  add(id: UUID, subject: string): Promise<void>
  reissue(familyId: UUID, id: UUID, subject: string, oldId: UUID): Promise<void>
  delete(familyId: UUID): Promise<void>
}

export class InvalidLastIssuedException extends Error {
  name = 'InvalidLastIssuedException'
  constructor() {
    super("The family's last issued token ID did not match.")
  }
}

export class TokenNotFoundException extends Error {
  name = 'TokenNotFoundException'
  constructor() {
    super('The token family could not be found.')
  }
}

export interface UserAttributes {
  id: string
  email: string | null
  email_verified: boolean
  phone_number: string | null
  phone_number_verified: boolean
  password: string
  name: string
  zoneinfo: string | undefined
}

export interface AddUserAttributes {
  email: string | undefined
  phone_number: string | undefined
  password: string
  name: string
}

export interface RegisterByEmailAttributes extends AddUserAttributes {
  email: string
}

export interface RegisterByPhoneNumberAttributes extends AddUserAttributes {
  phone_number: string
}

export class User implements UserAttributes {
  constructor(
    public id: string,
    public email: string | null,
    public email_verified: boolean,
    public phone_number: string | null,
    public phone_number_verified: boolean,
    public password: string,
    public name: string,
    public zoneinfo: string | undefined
  ) {}
}

export interface IUserRepository {
  ready: Promise<boolean>
  getUserByEmail(email: string): Promise<User>
  getUserByPhoneNumber(phone_number: string): Promise<User>
  registerByEmail(attributes: RegisterByEmailAttributes): Promise<User>
  registerByPhoneNumber(
    attributes: RegisterByPhoneNumberAttributes
  ): Promise<User>
}

enum ExceptionTypes {
  UnknownException = 'UnknownException',
  UnexpectedException = 'UnexpectedException',
  NotImplementedException = 'NotImplementedException',
  UndefinedAttributeException = 'UndefinedAttributeException',
  InvalidTypeException = 'InvalidTypeException',
  NotReadyException = 'NotReadyException',
  FileNotExistException = 'FileNotExistException',
  NotFoundException = 'NotFoundException',
}
export class UnknownException extends Error {
  name = ExceptionTypes.UnknownException
  constructor() {
    super("An unknown exception occured, we're not sure what went wrong.")
  }
}

export class UnexpectedException extends Error {
  name = ExceptionTypes.UnexpectedException
  constructor() {
    super(
      'A completely unexpected error occured, we thought all cases were covered here.'
    )
  }
}

export class NotImplementedException extends Error {
  name = ExceptionTypes.NotImplementedException
  constructor() {
    super('This function has no implementation.')
  }
}

export class UndefinedAttributeException extends Error {
  name = ExceptionTypes.UndefinedAttributeException
  constructor() {
    super('You are trying to access an undefined attribute.')
  }
}

export class InvalidTypeException extends Error {
  name = ExceptionTypes.InvalidTypeException
  constructor(cause: string) {
    super('An invalid type was provided.', { cause })
  }
}

export class NotReadyException extends Error {
  name = ExceptionTypes.NotReadyException
  constructor() {
    super('The class property was not ready yet.')
  }
}

export class FileNotExistException extends Error {
  name = ExceptionTypes.FileNotExistException
  constructor(cause: string) {
    super(`The file ${cause} does not exist.`)
  }
}

export class NotFoundException extends Error {
  name = ExceptionTypes.NotFoundException
  constructor() {
    super(`The requested resource does not exist.`)
  }
}

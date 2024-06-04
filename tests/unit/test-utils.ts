export class MockException extends Error {
  name = 'MockException'
  constructor() {
    super('This is a mock exception.')
  }
}

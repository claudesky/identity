/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  transform: {
    '.*\.ts$': ['ts-jest', {useESM: true}]
  },
  preset: 'ts-jest',
  testEnvironment: 'node',
  modulePathIgnorePatterns: ["dist"],
};

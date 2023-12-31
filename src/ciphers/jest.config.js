module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/*.test.ts'],
  reporters: [
    'default',
    ['jest-html-reporters', {
      publicPath: '../docs/ciphers',
      filename: 'test-report.html',
      expand: true,
    }],
  ]
};
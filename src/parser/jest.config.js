module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/*.test.ts'],
  reporters: [
    'default',
    ['jest-html-reporters', {
      publicPath: '../docs/encode-parser',
      filename: 'test-report.html',
      expand: true,
    }],
  ]
};
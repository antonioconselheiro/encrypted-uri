module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  reporters: [
    'default',
    ['jest-html-reporters', {
      publicPath: '../docs',
      filename: 'test-report.html',
      expand: true,
    }]
  ],
  transformIgnorePatterns: [
    '/node_modules/',
    '/packages/core/node_modules/',
    '/packages/ciphers/node_modules/',
  ]
};

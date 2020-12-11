const path = require('path');

module.exports = {
  mode: 'production',
  target: 'web',
  externals: ['node-forge'],
  output: {
    path: path.join(__dirname, 'dist'),
    filename: '[name].min.js',
    library: '[name]',
    libraryTarget: 'umd'
  },
  node: false,

  resolve: {
    alias: {
      // throw an error if trying to import 'crypto'
      // workaround for "node" feature not working in sub-dependencies
      crypto$: path.resolve(__dirname, 'no-crypto.js')
    }
  }
};

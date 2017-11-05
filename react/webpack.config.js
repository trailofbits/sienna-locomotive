 var path = require('path');
 var webpack = require('webpack');
 module.exports = {
     entry: './index.js',
     output: {
         path: path.resolve(__dirname, 'build'),
         filename: 'index.bundle.js'
     },
     module: {
         loaders: [
             {
                 test: /\.js$/,
                 exclude: /node_modules/,
                 loader: 'babel-loader',
                 query: {
                     presets: ['react', 'es2015']
                 }
             },
             {
                test: /\.css$/,  
                include: /styles/,  
                loaders: ['style-loader', 'css-loader'],
            }
         ]
     },
     stats: {
         colors: true
     }
     //devtool: 'source-map'
 };
